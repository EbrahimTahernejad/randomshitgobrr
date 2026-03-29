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
	initPollDelay = 500 * time.Millisecond
	maxPollDelay  = 10 * time.Second
	pollDelayMult = 2.0
	pollLimit     = 16
	pollNonceLen  = 4
)

var base32Enc = base32.StdEncoding.WithPadding(base32.NoPadding)

// ClientConn is a net.PacketConn suitable for use as a KCP transport.
// Writes are encoded as DNS TXT queries (VayDNS single-label format);
// reads come from raw ICMP Echo Requests sent by the server.
type ClientConn struct {
	*turbotunnel.QueuePacketConn
	cfg         Config
	clientID    turbotunnel.ClientID // 8-byte internal KCP session identifier
	dnsClientID []byte               // cfg.ClientIDLen bytes; sent in DNS queries and ICMP payloads
	domain      dns.Name
	pollChan    chan struct{}
}

// NewClientConn creates a ClientConn and starts its background goroutines.
// transport carries the actual DNS messages (UDP socket, DoH, DoT).
// addr is the DNS resolver address.
// domain is the tunnel domain, e.g. t.example.com.
// cfg controls wire-protocol parameters; use DefaultConfig() for normal operation.
// Requires root or CAP_NET_RAW for raw ICMP reception.
func NewClientConn(transport net.PacketConn, addr net.Addr, domain dns.Name, cfg Config) (*ClientConn, error) {
	clientID := turbotunnel.NewClientID()
	dnsClientID := make([]byte, cfg.ClientIDLen)
	if _, err := rand.Read(dnsClientID); err != nil {
		return nil, fmt.Errorf("generate DNS client ID: %w", err)
	}
	c := &ClientConn{
		QueuePacketConn: turbotunnel.NewQueuePacketConn(clientID, 0),
		cfg:             cfg,
		clientID:        clientID,
		dnsClientID:     dnsClientID,
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

// ClientID returns the internal KCP session identifier.
func (c *ClientConn) ClientID() turbotunnel.ClientID { return c.clientID }

// icmpRecvLoop listens for ICMP Echo Requests, filters by IcmpID and the
// 2-byte DNS client ID prefix in the payload, then unpacks bundled KCP packets
// and queues them for KCP to read.
func (c *ClientConn) icmpRecvLoop(conn *icmp.PacketConn) error {
	buf := make([]byte, 65536)
	for {
		n, _, _, err := conn.IPv4PacketConn().ReadFrom(buf)
		if err != nil {
			return err
		}

		msg, err := icmp.ParseMessage(1, buf[:n])
		if err != nil {
			continue
		}
		if msg.Type != ipv4.ICMPTypeEcho {
			continue
		}
		echo, ok := msg.Body.(*icmp.Echo)
		if !ok {
			continue
		}
		if echo.ID != c.cfg.IcmpID {
			continue
		}
		data := echo.Data
		if len(data) < c.cfg.ClientIDLen {
			continue
		}
		// Filter by DNS client ID prefix.
		if !bytes.Equal(data[:c.cfg.ClientIDLen], c.dnsClientID) {
			continue
		}

		// Unpack length-prefixed KCP packets from the ICMP payload.
		r := bytes.NewReader(data[c.cfg.ClientIDLen:])
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
// also sending empty polling queries on a timer.
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

// sendDNS encodes a KCP packet (or empty for a poll) as a DNS TXT query using
// the VayDNS wire format and sends it via transport.
//
// VayDNS encoding:
//   - Data query: [clientID:2][datalen:1][data]
//   - Poll query: [clientID:2][nonce:4]
//
// The encoded bytes are base32-encoded into at most one 63-byte label,
// ensuring the query name fits through resolvers that strip multi-label prefixes.
func (c *ClientConn) sendDNS(transport net.PacketConn, p []byte, addr net.Addr) error {
	var raw bytes.Buffer
	raw.Write(c.dnsClientID[:])
	if len(p) > 0 {
		if len(p) > 255 {
			return fmt.Errorf("packet too long: %d bytes", len(p))
		}
		raw.WriteByte(byte(len(p)))
		raw.Write(p)
	} else {
		// Poll: append random nonce for cache busting.
		io.CopyN(&raw, rand.Reader, pollNonceLen)
	}

	encoded := make([]byte, base32Enc.EncodedLen(raw.Len()))
	base32Enc.Encode(encoded, raw.Bytes())
	encoded = bytes.ToLower(encoded)

	// Limit to a single DNS label so the query passes through resolvers
	// that strip multi-label prefixes.
	if len(encoded) > c.cfg.MaxLabelLen {
		encoded = encoded[:c.cfg.MaxLabelLen]
	}

	labels := [][]byte{encoded}
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
			{Name: name, Type: c.cfg.RecordType, Class: dns.ClassIN},
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
