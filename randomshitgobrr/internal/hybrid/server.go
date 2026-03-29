package hybrid

import (
	"bytes"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"github.com/net2share/vaydns/dns"
	"github.com/net2share/vaydns/turbotunnel"
)

const (
	clientExpiry  = 5 * time.Minute
	icmpBundleMax = 1400 // max ICMP payload; bundle multiple KCP packets per datagram
	responseTTL   = 60
	maxDNSPayload = 1232
)

// ServerTransport manages the server side of the hybrid tunnel.
// DNS queries carry upstream KCP packets; ICMP Echo Requests carry downstream.
type ServerTransport struct {
	cfg        Config
	domain     dns.Name
	destIP     net.IP // client's public IP — destination of downstream ICMP
	spoofSrcIP net.IP
	ttConn     *turbotunnel.QueuePacketConn

	rawFd    int              // IPv4 raw socket for spoofed ICMP (IP_HDRINCL)
	icmpConn *icmp.PacketConn // normal ICMP send (no spoofing)
	icmpSeq  atomic.Uint32

	mu        sync.Mutex
	clientIPs map[turbotunnel.ClientID]net.IP
}

// NewServerTransport creates a ServerTransport.
// destIP is the client's public IPv4 address — all downstream ICMP is sent here.
// If spoofSrcIP is non-nil, downstream ICMP packets have it as their source address
// (requires root/CAP_NET_RAW and a raw socket with IP_HDRINCL).
// If spoofSrcIP is nil, ICMP is sent normally (source IP from OS routing).
// cfg must match the Config used by the client.
func NewServerTransport(domain dns.Name, destIP net.IP, spoofSrcIP net.IP, ttConn *turbotunnel.QueuePacketConn, cfg Config) (*ServerTransport, error) {
	st := &ServerTransport{
		cfg:        cfg,
		domain:     domain,
		destIP:     destIP,
		spoofSrcIP: spoofSrcIP,
		ttConn:     ttConn,
		rawFd:      -1,
		clientIPs:  make(map[turbotunnel.ClientID]net.IP),
	}

	if spoofSrcIP != nil && spoofSrcIP.To4() != nil {
		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
		if err != nil {
			return nil, fmt.Errorf("raw socket (needs root/CAP_NET_RAW): %w", err)
		}
		if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
			syscall.Close(fd)
			return nil, fmt.Errorf("setsockopt IP_HDRINCL: %w", err)
		}
		st.rawFd = fd
	} else {
		conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
		if err != nil {
			return nil, fmt.Errorf("icmp listen (needs root/CAP_NET_RAW): %w", err)
		}
		st.icmpConn = conn
	}

	return st, nil
}

// Close releases the raw socket or ICMP connection.
func (st *ServerTransport) Close() {
	if st.rawFd >= 0 {
		syscall.Close(st.rawFd)
	}
	if st.icmpConn != nil {
		st.icmpConn.Close()
	}
}

// RecvLoop reads DNS messages from dnsConn, routes upstream KCP packets into
// ttConn, tracks client IPs, and sends empty DNS responses.
// Blocks until dnsConn returns a non-temporary error.
func (st *ServerTransport) RecvLoop(dnsConn net.PacketConn) error {
	for {
		var buf [4096]byte
		n, addr, err := dnsConn.ReadFrom(buf[:])
		if err != nil {
			if nerr, ok := err.(net.Error); ok && nerr.Temporary() {
				continue
			}
			return err
		}
		go st.handleQuery(buf[:n], addr, dnsConn)
	}
}

func (st *ServerTransport) handleQuery(buf []byte, addr net.Addr, dnsConn net.PacketConn) {
	query, err := dns.MessageFromWireFormat(buf)
	if err != nil {
		log.Printf("handleQuery: parse error from %v: %v", addr, err)
		return
	}

	resp, payload := responseFor(&query, st.domain, st.cfg.RecordType)
	if resp == nil {
		return
	}

	// VayDNS wire format: [clientID:N][datalen:1][data]... or [clientID:N][nonce:4] for polls.
	if len(payload) < st.cfg.ClientIDLen {
		log.Printf("handleQuery: payload too short from %v (%d bytes, need at least %d for clientID)", addr, len(payload), st.cfg.ClientIDLen)
		if resp.Rcode() == dns.RcodeNoError {
			resp.Flags |= dns.RcodeNameError
		}
	} else {
		// Extract the client ID from the DNS payload.
		clientID := turbotunnel.ClientID(payload[:st.cfg.ClientIDLen])
		dnsClientID := payload[:st.cfg.ClientIDLen]
		payload = payload[st.cfg.ClientIDLen:]

		st.mu.Lock()
		isNew := false
		if _, known := st.clientIPs[clientID]; !known {
			st.clientIPs[clientID] = st.destIP
			isNew = true
			go st.icmpSendLoop(clientID, st.destIP)
		}
		st.mu.Unlock()
		if isNew {
			log.Printf("handleQuery: new client %x from %v → ICMP dest %v", dnsClientID, addr, st.destIP)
		}

		// Feed upstream KCP packets from the DNS query payload.
		if len(payload) <= pollNonceLen+1 {
			// Poll query: payload is just a nonce, no data.
			log.Printf("handleQuery: poll from %x @ %v (payload=%d bytes)", dnsClientID, addr, len(payload))
		} else {
			r := bytes.NewReader(payload)
			count := 0
			totalBytes := 0
			for {
				p, err := vaydnsNextPacket(r)
				if err != nil {
					break
				}
				if len(p) > 0 {
					st.ttConn.QueueIncoming(p, clientID)
					count++
					totalBytes += len(p)
				}
			}
			log.Printf("handleQuery: data from %x @ %v: %d KCP packet(s), %d bytes queued", dnsClientID, addr, count, totalBytes)
		}
	}

	// Send an empty DNS response — downstream data goes via ICMP.
	if resp.Rcode() == dns.RcodeNoError && len(resp.Question) == 1 {
		resp.Answer = []dns.RR{{
			Name:  resp.Question[0].Name,
			Type:  resp.Question[0].Type,
			Class: resp.Question[0].Class,
			TTL:   responseTTL,
			Data:  dns.EncodeRDataTXT([]byte{}),
		}}
	}
	respBuf, err := resp.WireFormat()
	if err != nil {
		return
	}
	if len(respBuf) > maxDNSPayload {
		respBuf = respBuf[:maxDNSPayload]
		respBuf[2] |= 0x02 // set TC bit
	}
	dnsConn.WriteTo(respBuf, addr)
}

// icmpSendLoop runs per active client: drains the KCP outgoing queue and sends
// the packets to the client's real IP as ICMP Echo Requests, bundling multiple
// KCP packets per ICMP datagram where possible.
func (st *ServerTransport) icmpSendLoop(clientID turbotunnel.ClientID, clientIP net.IP) {
	log.Printf("client %s up, sending ICMP to %v", clientID, clientIP)
	defer func() {
		st.mu.Lock()
		delete(st.clientIPs, clientID)
		st.mu.Unlock()
		log.Printf("client %s down", clientID)
	}()

	outgoing := st.ttConn.OutgoingQueue(clientID)
	idle := time.NewTimer(clientExpiry)
	defer idle.Stop()

	var overflow []byte // packet that didn't fit in the previous ICMP
	for {
		// Block for the first packet (or idle timeout).
		var p []byte
		if overflow != nil {
			p = overflow
			overflow = nil
		} else {
			select {
			case p = <-outgoing:
				if !idle.Stop() {
					select {
					case <-idle.C:
					default:
					}
				}
				idle.Reset(clientExpiry)
			case <-idle.C:
				return
			}
		}

		// Bundle greedily up to icmpBundleMax bytes.
		var payload bytes.Buffer
		payload.Write(clientID.Bytes()) // client ID prefix
		for p != nil {
			// Only check limit after the first packet; let oversized packets
			// through so they are at least attempted once.
			if payload.Len() > st.cfg.ClientIDLen && payload.Len()+2+len(p) > icmpBundleMax {
				overflow = p
				break
			}
			binary.Write(&payload, binary.BigEndian, uint16(len(p)))
			payload.Write(p)
			p = nil
			select {
			case p = <-outgoing:
			default:
			}
		}

		pktCount := 0
		scanBuf := payload.Bytes()[st.cfg.ClientIDLen:]
		sr := bytes.NewReader(scanBuf)
		for {
			var l uint16
			if binary.Read(sr, binary.BigEndian, &l) != nil {
				break
			}
			sr.Seek(int64(l), io.SeekCurrent)
			pktCount++
		}
		log.Printf("icmpSendLoop: → %v: %d KCP packet(s), %d bytes payload", clientIP, pktCount, payload.Len())
		if err := st.sendICMP(payload.Bytes(), clientIP); err != nil {
			log.Printf("ICMP send to %v: %v", clientIP, err)
		}
	}
}

func (st *ServerTransport) sendICMP(payload []byte, dstIP net.IP) error {
	if st.rawFd >= 0 {
		return st.sendICMPSpoofed(payload, dstIP)
	}
	return st.sendICMPNormal(payload, dstIP)
}

// sendICMPSpoofed builds a full IP+ICMP packet with a spoofed source address
// and sends it via the raw socket.
func (st *ServerTransport) sendICMPSpoofed(payload []byte, dstIP net.IP) error {
	src4 := st.spoofSrcIP.To4()
	dst4 := dstIP.To4()
	if src4 == nil || dst4 == nil {
		return fmt.Errorf("spoofed ICMP requires IPv4")
	}
	seq := uint16(st.icmpSeq.Add(1))

	ipLayer := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolICMPv4,
		SrcIP:    net.IP(src4),
		DstIP:    net.IP(dst4),
	}
	icmpLayer := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		Id:       uint16(st.cfg.IcmpID),
		Seq:      seq,
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		ipLayer, icmpLayer, gopacket.Payload(payload),
	); err != nil {
		return fmt.Errorf("serialize layers: %w", err)
	}
	var sa syscall.SockaddrInet4
	copy(sa.Addr[:], dst4)
	return syscall.Sendto(st.rawFd, buf.Bytes(), 0, &sa)
}

// sendICMPNormal sends an ICMP Echo Request without spoofing the source IP.
func (st *ServerTransport) sendICMPNormal(payload []byte, dstIP net.IP) error {
	seq := uint16(st.icmpSeq.Add(1))
	msg := &icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   st.cfg.IcmpID,
			Seq:  int(seq),
			Data: payload,
		},
	}
	b, err := msg.Marshal(nil)
	if err != nil {
		return err
	}
	_, err = st.icmpConn.WriteTo(b, &net.IPAddr{IP: dstIP})
	return err
}

// responseFor constructs a DNS response for a query addressed to domain.
// Returns (nil, nil) if the query should not be answered at all.
// Returns (resp, payload) where payload is the base32-decoded label prefix data.
// Adapted from vaydns-server for wire-format compatibility.
func responseFor(query *dns.Message, domain dns.Name, recordType uint16) (*dns.Message, []byte) {
	resp := &dns.Message{
		ID:       query.ID,
		Flags:    0x8000,
		Question: query.Question,
	}
	if query.Flags&0x8000 != 0 {
		return nil, nil // not a query
	}
	payloadSize := 0
	for _, rr := range query.Additional {
		if rr.Type != dns.RRTypeOPT {
			continue
		}
		if len(resp.Additional) != 0 {
			resp.Flags |= dns.RcodeFormatError
			return resp, nil
		}
		resp.Additional = append(resp.Additional, dns.RR{
			Name:  dns.Name{},
			Type:  dns.RRTypeOPT,
			Class: 4096,
			TTL:   0,
			Data:  []byte{},
		})
		version := (rr.TTL >> 16) & 0xff
		if version != 0 {
			resp.Flags |= dns.ExtendedRcodeBadVers & 0xf
			resp.Additional[0].TTL = (dns.ExtendedRcodeBadVers >> 4) << 24
			return resp, nil
		}
		payloadSize = int(rr.Class)
	}
	if payloadSize < 512 {
		payloadSize = 512
	}
	if len(query.Question) != 1 {
		resp.Flags |= dns.RcodeFormatError
		return resp, nil
	}
	question := query.Question[0]
	prefix, ok := question.Name.TrimSuffix(domain)
	if !ok {
		resp.Flags |= dns.RcodeNameError
		return resp, nil
	}
	resp.Flags |= 0x0400 // AA bit
	if query.Opcode() != 0 {
		resp.Flags |= dns.RcodeNotImplemented
		return resp, nil
	}
	if question.Type != recordType {
		resp.Flags |= dns.RcodeNameError
		return resp, nil
	}
	encoded := bytes.ToUpper(bytes.Join(prefix, nil))
	dec := base32.StdEncoding.WithPadding(base32.NoPadding)
	payload := make([]byte, dec.DecodedLen(len(encoded)))
	n, err := dec.Decode(payload, encoded)
	if err != nil {
		resp.Flags |= dns.RcodeNameError
		return resp, nil
	}
	payload = payload[:n]
	if payloadSize < maxDNSPayload {
		resp.Flags |= dns.RcodeFormatError
		return resp, nil
	}
	return resp, payload
}

// vaydnsNextPacket reads the next data packet from r using the VayDNS wire
// format: [datalen:1][data]. Returns io.EOF only when 0 bytes remain in r.
func vaydnsNextPacket(r *bytes.Reader) ([]byte, error) {
	prefix, err := r.ReadByte()
	if err != nil {
		return nil, err // may return real io.EOF here
	}
	p := make([]byte, int(prefix))
	_, err = io.ReadFull(r, p)
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return p, err
}

