// Package hybrid implements a split transport:
// upstream (client→server) via DNS TXT queries,
// downstream (server→client) via ICMP Echo Requests with spoofed source IP.
package hybrid

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"www.bamsoftware.com/git/dnstt.git/dns"
	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

const (
	numPadding        = 3
	numPaddingForPoll = 8
	initPollDelay     = 500 * time.Millisecond
	maxPollDelay      = 10 * time.Second
	pollDelayMult     = 2.0
	pollLimit         = 16

	// IcmpID is the ICMP identifier used for hybrid tunnel packets ("SP").
	IcmpID = 0x5350
)

var base32Enc = base32.StdEncoding.WithPadding(base32.NoPadding)

// ClientConn is a net.PacketConn suitable for use as a KCP transport.
// Writes are encoded as DNS TXT queries; reads come from raw ICMP Echo Requests
// sent by the server.
type ClientConn struct {
	*turbotunnel.QueuePacketConn
	clientID turbotunnel.ClientID
	domain   dns.Name
	pollChan chan struct{}
}

// NewClientConn creates a ClientConn and starts its background goroutines.
// transport carries the actual DNS messages (UDP socket, DoH, DoT).
// addr is the DNS resolver address.
// domain is the tunnel domain, e.g. t.example.com.
// Requires root or CAP_NET_RAW for raw ICMP reception.
func NewClientConn(transport net.PacketConn, addr net.Addr, domain dns.Name) (*ClientConn, error) {
	clientID := turbotunnel.NewClientID()
	c := &ClientConn{
		QueuePacketConn: turbotunnel.NewQueuePacketConn(clientID, 0),
		clientID:        clientID,
		domain:          domain,
		pollChan:        make(chan struct{}, pollLimit),
	}

	icmpConn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, fmt.Errorf("listen ICMP (requires root/CAP_NET_RAW): %w", err)
	}

	// Drain DNS responses — downstream data arrives via ICMP instead.
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, _, err := transport.ReadFrom(buf); err != nil {
				return
			}
		}
	}()

	go func() {
		defer icmpConn.Close()
		if err := c.icmpRecvLoop(icmpConn); err != nil {
			log.Printf("icmpRecvLoop: %v", err)
		}
	}()

	go func() {
		if err := c.dnsSendLoop(transport, addr); err != nil {
			log.Printf("dnsSendLoop: %v", err)
		}
	}()

	return c, nil
}

// ClientID returns the session identifier embedded in every DNS query.
func (c *ClientConn) ClientID() turbotunnel.ClientID { return c.clientID }

// icmpRecvLoop listens for ICMP Echo Requests, filters by IcmpID and the
// 8-byte ClientID prefix in the payload, then unpacks bundled KCP packets
// and queues them for KCP to read.
func (c *ClientConn) icmpRecvLoop(conn *icmp.PacketConn) error {
	log.Printf("icmpRecvLoop: started, listening for ICMP (clientID=%s)", c.clientID)
	buf := make([]byte, 65536)
	for {
		n, _, src, err := conn.IPv4PacketConn().ReadFrom(buf)
		if err != nil {
			return err
		}
		log.Printf("icmpRecvLoop: raw recv %d bytes from %v", n, src)

		msg, err := icmp.ParseMessage(1, buf[:n])
		if err != nil {
			log.Printf("icmpRecvLoop: parse error: %v", err)
			continue
		}
		log.Printf("icmpRecvLoop: type=%v", msg.Type)

		if msg.Type != ipv4.ICMPTypeEcho {
			continue
		}
		echo, ok := msg.Body.(*icmp.Echo)
		if !ok {
			log.Printf("icmpRecvLoop: body not *icmp.Echo")
			continue
		}
		log.Printf("icmpRecvLoop: echo id=%#x seq=%d data=%d bytes", echo.ID, echo.Seq, len(echo.Data))
		if echo.ID != IcmpID {
			log.Printf("icmpRecvLoop: id mismatch (want %#x)", IcmpID)
			continue
		}
		data := echo.Data
		if len(data) < 8 {
			log.Printf("icmpRecvLoop: payload too short (%d bytes)", len(data))
			continue
		}
		var pktID turbotunnel.ClientID
		copy(pktID[:], data[:8])
		if pktID != c.clientID {
			log.Printf("icmpRecvLoop: clientID mismatch (got %x, want %x)", pktID, c.clientID)
			continue
		}
		log.Printf("icmpRecvLoop: tunnel packet accepted, unpacking KCP payloads")

		// Unpack length-prefixed KCP packets from the ICMP payload.
		r := bytes.NewReader(data[8:])
		any := false
		for {
			var length uint16
			if err := binary.Read(r, binary.BigEndian, &length); err != nil {
				break
			}
			p := make([]byte, length)
			if _, err := io.ReadFull(r, p); err != nil {
				break
			}
			any = true
			log.Printf("icmpRecvLoop: queued KCP packet %d bytes", length)
			c.QueuePacketConn.QueueIncoming(p, turbotunnel.DummyAddr{})
		}
		if any {
			select {
			case c.pollChan <- struct{}{}:
			default:
			}
		}
	}
}

// dnsSendLoop reads outgoing KCP packets and sends each as a DNS TXT query,
// also sending empty polling queries on a timer (matching dnstt behavior).
func (c *ClientConn) dnsSendLoop(transport net.PacketConn, addr net.Addr) error {
	pollDelay := initPollDelay
	pollTimer := time.NewTimer(pollDelay)
	for {
		var p []byte
		outgoing := c.QueuePacketConn.OutgoingQueue(addr)
		pollTimerExpired := false

		select {
		case p = <-outgoing:
		default:
			select {
			case p = <-outgoing:
			case <-c.pollChan:
			case <-pollTimer.C:
				pollTimerExpired = true
			}
		}

		if len(p) > 0 {
			select {
			case <-c.pollChan:
			default:
			}
		}

		if pollTimerExpired {
			pollDelay = time.Duration(float64(pollDelay) * pollDelayMult)
			if pollDelay > maxPollDelay {
				pollDelay = maxPollDelay
			}
		} else {
			if !pollTimer.Stop() {
				select {
				case <-pollTimer.C:
				default:
				}
			}
			pollDelay = initPollDelay
		}
		pollTimer.Reset(pollDelay)

		if err := c.sendDNS(transport, p, addr); err != nil {
			log.Printf("sendDNS: %v", err)
		}
	}
}

// sendDNS encodes a KCP packet (or empty for a poll) as a DNS TXT query and
// sends it via transport. The encoding is identical to dnstt-client.
func (c *ClientConn) sendDNS(transport net.PacketConn, p []byte, addr net.Addr) error {
	if len(p) >= 224 {
		return fmt.Errorf("packet too long: %d bytes", len(p))
	}

	var raw bytes.Buffer
	raw.Write(c.clientID[:])
	n := numPadding
	if len(p) == 0 {
		n = numPaddingForPoll
	}
	raw.WriteByte(byte(224 + n))
	io.CopyN(&raw, rand.Reader, int64(n))
	if len(p) > 0 {
		raw.WriteByte(byte(len(p)))
		raw.Write(p)
	}

	encoded := make([]byte, base32Enc.EncodedLen(raw.Len()))
	base32Enc.Encode(encoded, raw.Bytes())
	encoded = bytes.ToLower(encoded)

	labels := splitLabels(encoded, 63)
	labels = append(labels, c.domain...)
	name, err := dns.NewName(labels)
	if err != nil {
		return err
	}

	var id uint16
	binary.Read(rand.Reader, binary.BigEndian, &id)
	query := &dns.Message{
		ID:    id,
		Flags: 0x0100,
		Question: []dns.Question{
			{Name: name, Type: dns.RRTypeTXT, Class: dns.ClassIN},
		},
		Additional: []dns.RR{
			{Name: dns.Name{}, Type: dns.RRTypeOPT, Class: 4096, TTL: 0, Data: []byte{}},
		},
	}
	buf, err := query.WireFormat()
	if err != nil {
		return err
	}
	_, err = transport.WriteTo(buf, addr)
	return err
}

// splitLabels breaks p into subslices of at most n bytes.
func splitLabels(p []byte, n int) [][]byte {
	var result [][]byte
	for len(p) > 0 {
		sz := len(p)
		if sz > n {
			sz = n
		}
		result = append(result, p[:sz])
		p = p[sz:]
	}
	return result
}

// DNSNameCapacity returns the number of raw bytes that fit in the encoded
// label prefix of a DNS name before the given domain suffix.
func DNSNameCapacity(domain dns.Name) int {
	capacity := 255 - 1 // total name length minus null terminator
	for _, label := range domain {
		capacity -= len(label) + 1
	}
	capacity = capacity * 63 / 64 // label length prefix overhead
	capacity = capacity * 5 / 8   // base32 decode
	return capacity
}
