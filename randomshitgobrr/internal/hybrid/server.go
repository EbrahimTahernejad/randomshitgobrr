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
	"www.bamsoftware.com/git/dnstt.git/dns"
	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
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
	domain     dns.Name
	destIP     net.IP // client's public IP — destination of downstream ICMP
	spoofSrcIP net.IP
	ttConn     *turbotunnel.QueuePacketConn

	rawFd    int            // IPv4 raw socket for spoofed ICMP (IP_HDRINCL)
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
func NewServerTransport(domain dns.Name, destIP net.IP, spoofSrcIP net.IP, ttConn *turbotunnel.QueuePacketConn) (*ServerTransport, error) {
	st := &ServerTransport{
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
		return
	}

	resp, payload := responseFor(&query, st.domain)
	if resp == nil {
		return
	}

	var clientID turbotunnel.ClientID
	n := copy(clientID[:], payload)
	payload = payload[n:]

	if n == len(clientID) {
		st.mu.Lock()
		if _, known := st.clientIPs[clientID]; !known {
			st.clientIPs[clientID] = st.destIP
			go st.icmpSendLoop(clientID, st.destIP)
		}
		st.mu.Unlock()
		// Feed upstream KCP packets from the DNS query payload.
		r := bytes.NewReader(payload)
		for {
			p, err := serverNextPacket(r)
			if err != nil {
				break
			}
			st.ttConn.QueueIncoming(p, clientID)
		}
	} else if resp.Rcode() == dns.RcodeNoError {
		resp.Flags |= dns.RcodeNameError
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
		payload.Write(clientID[:])
		for p != nil {
			// Only check limit after the first packet; let oversized packets
			// through so they are at least attempted once.
			if payload.Len() > 8 && payload.Len()+2+len(p) > icmpBundleMax {
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
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0),
		Id:       IcmpID,
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
		Type: ipv4.ICMPTypeEchoReply,
		Code: 0,
		Body: &icmp.Echo{
			ID:   IcmpID,
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
// Copied verbatim from dnstt-server for wire-format compatibility.
func responseFor(query *dns.Message, domain dns.Name) (*dns.Message, []byte) {
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
	if question.Type != dns.RRTypeTXT {
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

// serverNextPacket reads the next data packet from r, skipping padding bytes.
// Padding is encoded with a prefix byte >= 0xe0 (length = prefix - 0xe0).
// Data is encoded with a prefix byte < 0xe0 (length = prefix).
// This matches the encoding used by the hybrid client's sendDNS method.
func serverNextPacket(r *bytes.Reader) ([]byte, error) {
	wrap := func(err error) error {
		if err == io.EOF {
			return io.ErrUnexpectedEOF
		}
		return err
	}
	for {
		prefix, err := r.ReadByte()
		if err != nil {
			return nil, err // may return real io.EOF here
		}
		if prefix >= 224 {
			paddingLen := int64(prefix - 224)
			if _, err := io.CopyN(io.Discard, r, paddingLen); err != nil {
				return nil, wrap(err)
			}
		} else {
			p := make([]byte, int(prefix))
			if _, err := io.ReadFull(r, p); err != nil {
				return nil, wrap(err)
			}
			return p, nil
		}
	}
}

