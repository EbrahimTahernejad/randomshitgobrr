package hybrid

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"github.com/net2share/vaydns/turbotunnel"
)

const socksMTU = 1400

// SocksClientConn is a net.PacketConn for use as a KCP transport in SOCKS uplink mode.
//
// Uplink (client→server): KCP packets sent as length-prefixed frames over a TCP
// connection (typically established through a SOCKS5 proxy).
// Downlink (server→client): ICMP Echo Requests or spoofed UDP, identical to DNS mode.
//
// Wire format on the TCP stream:
//
//	[clientID: cfg.ClientIDLen bytes]   — sent once at connection start
//	[uint16 BE length][KCP data]        — one frame per KCP packet, repeated
type SocksClientConn struct {
	*turbotunnel.QueuePacketConn
	cfg        Config
	clientID   turbotunnel.ClientID
	recvCloser io.Closer
}

// SocksMTU returns the recommended KCP MTU for SOCKS uplink mode.
// Unconstrained by DNS label length — uses a standard 1400-byte payload.
func SocksMTU() int { return socksMTU }

// NewSocksClientConn creates a SocksClientConn that sends upstream KCP packets
// over tcpConn and receives downstream data via ICMP or plain UDP (cfg.UDPPort).
//
// tcpConn must already be connected to the server (directly or via SOCKS5).
// Requires root or CAP_NET_RAW for ICMP reception (same as NewClientConn).
func NewSocksClientConn(tcpConn net.Conn, cfg Config) (*SocksClientConn, error) {
	clientID := turbotunnel.NewClientID(cfg.ClientIDLen)
	c := &SocksClientConn{
		QueuePacketConn: turbotunnel.NewQueuePacketConn(clientID, 0),
		cfg:             cfg,
		clientID:        clientID,
	}

	if cfg.Verbose {
		log.Printf("socks: clientID=%s icmpID=%#x udpPort=%d", clientID, cfg.IcmpID, cfg.UDPPort)
	}

	// Register this session with the server by writing our clientID first.
	if _, err := tcpConn.Write(clientID.Bytes()); err != nil {
		return nil, fmt.Errorf("send clientID: %w", err)
	}

	// Start downstream receive loop (ICMP or plain UDP).
	if cfg.UDPPort > 0 {
		udpConn, err := net.ListenUDP("udp", &net.UDPAddr{Port: cfg.UDPPort})
		if err != nil {
			return nil, fmt.Errorf("listen UDP port %d: %w", cfg.UDPPort, err)
		}
		c.recvCloser = udpConn
		go func() {
			if err := socksUDPRecvLoop(c.QueuePacketConn, udpConn, cfg, clientID); err != nil {
				if err.Error() != "use of closed network connection" {
					log.Printf("socks udpRecvLoop: %v", err)
				}
			}
		}()
	} else {
		icmpConn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
		if err != nil {
			return nil, fmt.Errorf("listen ICMP (requires root/CAP_NET_RAW): %w", err)
		}
		c.recvCloser = icmpConn
		go func() {
			if err := socksICMPRecvLoop(c.QueuePacketConn, icmpConn, cfg, clientID); err != nil {
				log.Printf("socks icmpRecvLoop: %v", err)
			}
		}()
	}

	// Start TCP uplink send loop.
	go func() {
		if err := socksTCPSendLoop(c.QueuePacketConn, tcpConn, cfg); err != nil && err != io.EOF {
			log.Printf("socks tcpSendLoop: %v", err)
		}
	}()

	return c, nil
}

// ClientID returns the session identifier used on the wire.
func (c *SocksClientConn) ClientID() turbotunnel.ClientID { return c.clientID }

// Close shuts down the SocksClientConn and its background goroutines.
func (c *SocksClientConn) Close() error {
	if c.recvCloser != nil {
		c.recvCloser.Close()
	}
	return c.QueuePacketConn.Close()
}

// socksTCPSendLoop drains the KCP outgoing queue and writes each packet to
// tcpConn as a two-byte big-endian length prefix followed by the data.
// No polling is needed: SMUX keepalives keep the session alive.
func socksTCPSendLoop(qpc *turbotunnel.QueuePacketConn, tcpConn net.Conn, cfg Config) error {
	defer tcpConn.Close()
	outgoing := qpc.OutgoingQueue(turbotunnel.DummyAddr{})
	for {
		p, ok := <-outgoing
		if !ok {
			return nil
		}
		if len(p) == 0 {
			continue
		}
		frame := make([]byte, 2+len(p))
		binary.BigEndian.PutUint16(frame, uint16(len(p)))
		copy(frame[2:], p)
		if _, err := tcpConn.Write(frame); err != nil {
			return err
		}
		if cfg.Verbose {
			log.Printf("socks: → %d bytes", len(p))
		}
	}
}

// socksICMPRecvLoop listens for ICMP Echo Requests, filters by IcmpID and clientID,
// unpacks bundled KCP packets, and queues them into qpc.
// Identical logic to ClientConn.icmpRecvLoop but without DNS polling signals.
func socksICMPRecvLoop(qpc *turbotunnel.QueuePacketConn, conn *icmp.PacketConn, cfg Config, clientID turbotunnel.ClientID) error {
	buf := make([]byte, 65536)
	idBytes := clientID.Bytes()
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
		if !ok || echo.ID != cfg.IcmpID {
			continue
		}
		data := echo.Data
		if len(data) < len(idBytes) || !bytes.Equal(data[:len(idBytes)], idBytes) {
			if cfg.Verbose {
				log.Printf("socks icmpRecvLoop: clientID mismatch, skipping")
			}
			continue
		}
		r := bytes.NewReader(data[len(idBytes):])
		count := 0
		for {
			var length uint16
			if binary.Read(r, binary.BigEndian, &length) != nil {
				break
			}
			p := make([]byte, length)
			if _, err := io.ReadFull(r, p); err != nil {
				break
			}
			qpc.QueueIncoming(p, turbotunnel.DummyAddr{})
			count++
		}
		if cfg.Verbose && count > 0 {
			log.Printf("socks icmpRecvLoop: queued %d KCP packet(s)", count)
		}
	}
}

// socksUDPRecvLoop listens on a UDP port for downstream packets from the server,
// filters by clientID, unpacks bundled KCP packets, and queues them into qpc.
// Identical logic to ClientConn.udpRecvLoop but without DNS polling signals.
func socksUDPRecvLoop(qpc *turbotunnel.QueuePacketConn, conn *net.UDPConn, cfg Config, clientID turbotunnel.ClientID) error {
	buf := make([]byte, 65536)
	idBytes := clientID.Bytes()
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			return err
		}
		data := buf[:n]
		if len(data) < len(idBytes) || !bytes.Equal(data[:len(idBytes)], idBytes) {
			continue
		}
		r := bytes.NewReader(data[len(idBytes):])
		count := 0
		for {
			var length uint16
			if binary.Read(r, binary.BigEndian, &length) != nil {
				break
			}
			p := make([]byte, length)
			if _, err := io.ReadFull(r, p); err != nil {
				break
			}
			qpc.QueueIncoming(p, turbotunnel.DummyAddr{})
			count++
		}
		if cfg.Verbose && count > 0 {
			log.Printf("socks udpRecvLoop: queued %d KCP packet(s)", count)
		}
	}
}
