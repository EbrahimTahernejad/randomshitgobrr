// hybrid-client is the client side of the hybrid DNS+ICMP tunnel.
//
// Upstream (client→server): DNS TXT queries via DOMAIN, or TCP via a SOCKS5 proxy.
// Downstream (server→client): ICMP Echo Requests or spoofed UDP on the raw socket.
//
// DNS uplink usage:
//
//	hybrid-client [-udp ADDR|-doh URL|-dot ADDR] -pubkey-file FILE DOMAIN LOCALADDR
//
// SOCKS uplink usage:
//
//	hybrid-client -socks5 PROXY -tcp-server HOST:PORT -pubkey-file FILE LOCALADDR
//
// Examples:
//
//	hybrid-client -udp 8.8.8.8:53 -pubkey-file server.pub t.example.com 127.0.0.1:7000
//	hybrid-client -socks5 proxy.corp:1080 -tcp-server 1.2.3.4:443 -pubkey-file server.pub 127.0.0.1:7000
//
// Requires root or CAP_NET_RAW for raw ICMP reception.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"golang.org/x/net/proxy"
	"github.com/user/randomshitgobrr/internal/hybrid"
	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
	"github.com/net2share/vaydns/dns"
	"github.com/net2share/vaydns/noise"
	"github.com/net2share/vaydns/turbotunnel"
)

const idleTimeout = 2 * time.Minute

func handle(local *net.TCPConn, sess *smux.Session, conv uint32) error {
	stream, err := sess.OpenStream()
	if err != nil {
		return fmt.Errorf("open stream: %v", err)
	}
	defer stream.Close()
	log.Printf("stream %08x:%d open", conv, stream.ID())
	defer log.Printf("stream %08x:%d close", conv, stream.ID())

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := io.Copy(stream, local)
		if err != nil && err != io.EOF && !errors.Is(err, io.ErrClosedPipe) {
			log.Printf("stream %08x:%d copy stream←local: %v", conv, stream.ID(), err)
		}
		local.CloseRead()
		stream.Close()
	}()
	go func() {
		defer wg.Done()
		_, err := io.Copy(local, stream)
		if err != nil && err != io.EOF && !errors.Is(err, io.ErrClosedPipe) {
			log.Printf("stream %08x:%d copy local←stream: %v", conv, stream.ID(), err)
		}
		local.CloseWrite()
	}()
	wg.Wait()
	return nil
}

// runSession sets up KCP → Noise → SMUX over pconn and listens for local TCP
// connections on localAddr. mtu is the KCP MTU to use.
func runSession(pconn net.PacketConn, mtu int, pubkey []byte, localAddr *net.TCPAddr) error {
	conn, err := kcp.NewConn2(turbotunnel.DummyAddr{}, nil, 0, 0, pconn)
	if err != nil {
		return fmt.Errorf("KCP conn: %v", err)
	}
	defer conn.Close()
	log.Printf("KCP session %08x", conn.GetConv())
	conn.SetStreamMode(true)
	conn.SetNoDelay(0, 0, 0, 1)
	conn.SetWindowSize(turbotunnel.QueueSize/2, turbotunnel.QueueSize/2)
	if !conn.SetMtu(mtu) {
		return fmt.Errorf("SetMtu(%d) failed", mtu)
	}

	log.Printf("KCP session %08x: noise handshake start", conn.GetConv())
	rw, err := noise.NewClient(conn, pubkey)
	if err != nil {
		return fmt.Errorf("noise handshake: %v", err)
	}
	log.Printf("KCP session %08x: noise handshake done", conn.GetConv())

	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = 2
	smuxConfig.KeepAliveTimeout = idleTimeout
	smuxConfig.MaxStreamBuffer = 1 * 1024 * 1024
	sess, err := smux.Client(rw, smuxConfig)
	if err != nil {
		return fmt.Errorf("smux: %v", err)
	}
	defer sess.Close()

	ln, err := net.ListenTCP("tcp", localAddr)
	if err != nil {
		return fmt.Errorf("listen %v: %v", localAddr, err)
	}
	defer ln.Close()
	log.Printf("listening on %v", ln.Addr())

	for {
		local, err := ln.Accept()
		if err != nil {
			if nerr, ok := err.(net.Error); ok && nerr.Temporary() {
				continue
			}
			return err
		}
		go func() {
			defer local.Close()
			if err := handle(local.(*net.TCPConn), sess, conn.GetConv()); err != nil {
				log.Printf("handle: %v", err)
			}
		}()
	}
}

// run is the DNS-uplink entry point.
func run(pubkey []byte, domain dns.Name, localAddr *net.TCPAddr, resolvers []net.Addr, broadcast int, transport net.PacketConn, cfg hybrid.Config) error {
	defer transport.Close()

	mtu := cfg.MaxKCPMTU()
	log.Printf("DNS uplink: KCP MTU %d (clientIDLen=%d icmpID=%#x maxLabelLen=%d recordType=%d)",
		mtu, cfg.ClientIDLen, cfg.IcmpID, cfg.MaxLabelLen, cfg.RecordType)

	pconn, err := hybrid.NewClientConn(transport, resolvers, broadcast, domain, cfg)
	if err != nil {
		return fmt.Errorf("hybrid conn: %v", err)
	}

	return runSession(pconn, mtu, pubkey, localAddr)
}

// runSocks is the SOCKS-uplink entry point.
func runSocks(pubkey []byte, localAddr *net.TCPAddr, socksAddr, serverAddr string, mtu int, cfg hybrid.Config) error {
	log.Printf("SOCKS uplink: connecting via %s to %s", socksAddr, serverAddr)

	dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		return fmt.Errorf("socks5 dialer: %w", err)
	}
	tcpConn, err := dialer.Dial("tcp", serverAddr)
	if err != nil {
		return fmt.Errorf("socks5 dial %s: %w", serverAddr, err)
	}

	log.Printf("SOCKS uplink: KCP MTU %d (clientIDLen=%d icmpID=%#x)", mtu, cfg.ClientIDLen, cfg.IcmpID)

	pconn, err := hybrid.NewSocksClientConn(tcpConn, cfg)
	if err != nil {
		tcpConn.Close()
		return fmt.Errorf("socks client conn: %w", err)
	}

	return runSession(pconn, mtu, pubkey, localAddr)
}

func readKey(filename string) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return noise.ReadKey(f)
}

// multiFlag is a repeatable string flag (e.g. -udp 8.8.8.8:53 -udp 1.1.1.1:53).
type multiFlag []string

func (f *multiFlag) String() string {
	if f == nil || len(*f) == 0 {
		return ""
	}
	return (*f)[0]
}
func (f *multiFlag) Set(v string) error {
	*f = append(*f, v)
	return nil
}

func main() {
	var dohURL, dotAddr string
	var udpAddrs multiFlag
	var pubkeyFile, pubkeyHex string
	var verbose bool
	var broadcast int
	var socksAddr, tcpServer string
	var socksMTU int

	defCfg := hybrid.DefaultConfig()
	var clientIDLen, icmpID, maxLabelLen int
	flag.StringVar(&dohURL, "doh", "", "DNS-over-HTTPS resolver URL")
	flag.StringVar(&dotAddr, "dot", "", "DNS-over-TLS resolver address")
	flag.Var(&udpAddrs, "udp", "UDP DNS resolver address (repeatable for round-robin)")
	flag.StringVar(&socksAddr, "socks5", "", "SOCKS5 proxy address for TCP uplink (host:port)")
	flag.StringVar(&tcpServer, "tcp-server", "", "server TCP address for SOCKS uplink (host:port); required with -socks5")
	flag.IntVar(&socksMTU, "mtu", hybrid.SocksMTU(), "KCP MTU for SOCKS uplink")
	flag.StringVar(&pubkeyFile, "pubkey-file", "", "server public key file")
	flag.StringVar(&pubkeyHex, "pubkey", "", fmt.Sprintf("server public key (%d hex digits)", noise.KeyLen*2))
	flag.IntVar(&clientIDLen, "client-id-len", defCfg.ClientIDLen, "bytes used as DNS/ICMP session ID (must match server)")
	flag.IntVar(&icmpID, "icmp-id", defCfg.IcmpID, "ICMP Echo identifier for tunnel packets (must match server)")
	flag.IntVar(&maxLabelLen, "max-label-len", defCfg.MaxLabelLen, "max base32 chars per DNS label (must match server)")
	var recordTypeStr string
	flag.StringVar(&recordTypeStr, "record-type", "txt", "DNS query type: txt, cname, a, aaaa, mx, ns, srv (must match server)")
	flag.BoolVar(&verbose, "verbose", false, "enable per-packet diagnostic logging")
	flag.IntVar(&broadcast, "broadcast", 1, "resolvers to send each packet to (1 = round-robin, >1 = redundant sends)")
	var udpPort int
	flag.IntVar(&udpPort, "downstream-udp-port", 0, "listen on this UDP port for downstream from server instead of ICMP (must match server, 0=ICMP)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr,
			"Usage (DNS uplink):  %s [-udp ADDR ...|-doh URL|-dot ADDR] -pubkey-file FILE DOMAIN LOCALADDR\n"+
				"Usage (SOCKS uplink): %s -socks5 PROXY -tcp-server HOST:PORT -pubkey-file FILE LOCALADDR\n\n",
			os.Args[0], os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.LUTC)

	var pubkey []byte
	var err error
	switch {
	case pubkeyFile != "" && pubkeyHex != "":
		fmt.Fprintln(os.Stderr, "only one of -pubkey and -pubkey-file allowed")
		os.Exit(1)
	case pubkeyFile != "":
		pubkey, err = readKey(pubkeyFile)
	case pubkeyHex != "":
		pubkey, err = noise.DecodeKey(pubkeyHex)
	default:
		fmt.Fprintln(os.Stderr, "-pubkey or -pubkey-file required")
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "pubkey: %v\n", err)
		os.Exit(1)
	}

	recordType, err := hybrid.ParseRecordType(recordTypeStr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	cfg := hybrid.Config{
		ClientIDLen: clientIDLen,
		IcmpID:      icmpID,
		MaxLabelLen: maxLabelLen,
		RecordType:  recordType,
		UDPPort:     udpPort,
		Verbose:     verbose,
	}

	// ── SOCKS uplink mode ────────────────────────────────────────────────────
	if socksAddr != "" {
		if tcpServer == "" {
			fmt.Fprintln(os.Stderr, "-tcp-server required with -socks5")
			os.Exit(1)
		}
		if flag.NArg() != 1 {
			flag.Usage()
			os.Exit(1)
		}
		localAddr, err := net.ResolveTCPAddr("tcp", flag.Arg(0))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := runSocks(pubkey, localAddr, socksAddr, tcpServer, socksMTU, cfg); err != nil {
			log.Fatal(err)
		}
		return
	}

	// ── DNS uplink mode ──────────────────────────────────────────────────────
	if flag.NArg() != 2 {
		flag.Usage()
		os.Exit(1)
	}
	domain, err := dns.ParseName(flag.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid domain: %v\n", err)
		os.Exit(1)
	}
	localAddr, err := net.ResolveTCPAddr("tcp", flag.Arg(1))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	var resolvers []net.Addr
	var transport net.PacketConn
	n := 0

	if dohURL != "" {
		n++
		resolvers = []net.Addr{turbotunnel.DummyAddr{}}
		rt := http.DefaultTransport.(*http.Transport).Clone()
		rt.Proxy = nil
		transport = newDOHConn(rt, dohURL)
	}
	if dotAddr != "" {
		n++
		resolvers = []net.Addr{turbotunnel.DummyAddr{}}
		transport = newDOTConn(dotAddr)
	}
	if len(udpAddrs) > 0 {
		n++
		for _, s := range udpAddrs {
			addr, resolveErr := net.ResolveUDPAddr("udp", s)
			if resolveErr != nil {
				fmt.Fprintln(os.Stderr, resolveErr)
				os.Exit(1)
			}
			resolvers = append(resolvers, addr)
		}
		transport, err = net.ListenUDP("udp", nil)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	if n == 0 {
		fmt.Fprintln(os.Stderr, "one of -udp, -doh, -dot, -socks5 required")
		os.Exit(1)
	}
	if n > 1 {
		fmt.Fprintln(os.Stderr, "only one of -udp, -doh, -dot allowed")
		os.Exit(1)
	}

	if err := run(pubkey, domain, localAddr, resolvers, broadcast, transport, cfg); err != nil {
		log.Fatal(err)
	}
}

// dohConn is a minimal DNS-over-HTTPS PacketConn.
type dohConn struct {
	rt   http.RoundTripper
	url  string
	recv chan []byte
}

func newDOHConn(rt http.RoundTripper, url string) *dohConn {
	return &dohConn{rt: rt, url: url, recv: make(chan []byte, 32)}
}

func (c *dohConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	req, err := http.NewRequestWithContext(context.Background(), "POST", c.url, bytes.NewReader(p))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	go func() {
		resp, err := c.rt.RoundTrip(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return
		}
		select {
		case c.recv <- body:
		default:
		}
	}()
	return len(p), nil
}

func (c *dohConn) ReadFrom(p []byte) (int, net.Addr, error) {
	data := <-c.recv
	return copy(p, data), turbotunnel.DummyAddr{}, nil
}

func (c *dohConn) Close() error                       { return nil }
func (c *dohConn) LocalAddr() net.Addr                { return turbotunnel.DummyAddr{} }
func (c *dohConn) SetDeadline(_ time.Time) error      { return nil }
func (c *dohConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *dohConn) SetWriteDeadline(_ time.Time) error { return nil }

// dotConn is a minimal DNS-over-TLS PacketConn.
// Each query opens a new TLS connection (simple but not efficient).
type dotConn struct {
	addr string
	recv chan []byte
}

func newDOTConn(addr string) *dotConn {
	return &dotConn{addr: addr, recv: make(chan []byte, 32)}
}

func (c *dotConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	go func() {
		conn, err := tls.Dial("tcp", c.addr, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		// DNS-over-TLS uses a 2-byte length prefix.
		frame := make([]byte, 2+len(p))
		frame[0] = byte(len(p) >> 8)
		frame[1] = byte(len(p))
		copy(frame[2:], p)
		if _, err := conn.Write(frame); err != nil {
			return
		}
		var lenBuf [2]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return
		}
		n := int(lenBuf[0])<<8 | int(lenBuf[1])
		buf := make([]byte, n)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		select {
		case c.recv <- buf:
		default:
		}
	}()
	return len(p), nil
}

func (c *dotConn) ReadFrom(p []byte) (int, net.Addr, error) {
	data := <-c.recv
	return copy(p, data), turbotunnel.DummyAddr{}, nil
}

func (c *dotConn) Close() error                       { return nil }
func (c *dotConn) LocalAddr() net.Addr                { return turbotunnel.DummyAddr{} }
func (c *dotConn) SetDeadline(_ time.Time) error      { return nil }
func (c *dotConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *dotConn) SetWriteDeadline(_ time.Time) error { return nil }
