// hybrid-server is the server side of the hybrid DNS+ICMP tunnel.
//
// Upstream (client→server): DNS TXT queries on -udp port.
// Downstream (server→client): ICMP Echo Requests with optional spoofed source IP.
//
// Usage:
//
//	hybrid-server -gen-key [-privkey-file FILE] [-pubkey-file FILE]
//	hybrid-server -udp ADDR [-privkey-file FILE] [-spoof-src IP] DOMAIN UPSTREAMADDR
//
// Example:
//
//	hybrid-server -gen-key -privkey-file server.key -pubkey-file server.pub
//	hybrid-server -udp :53 -privkey-file server.key -spoof-src 1.1.1.1 t.example.com 127.0.0.1:8000
//
// Requires root: DNS binding on :53 and raw ICMP socket.
//
// On the server, suppress kernel ICMP auto-replies so clients don't see duplicates:
//
//	echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/user/randomshitgobrr/internal/hybrid"
	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
	"github.com/net2share/vaydns/dns"
	"github.com/net2share/vaydns/noise"
	"github.com/net2share/vaydns/turbotunnel"
)

const (
	idleTimeout         = 2 * time.Minute
	upstreamDialTimeout = 30 * time.Second
)

func handleStream(stream *smux.Stream, upstream string, conv uint32) error {
	dialer := net.Dialer{Timeout: upstreamDialTimeout}
	upConn, err := dialer.Dial("tcp", upstream)
	if err != nil {
		return fmt.Errorf("dial %s: %v", upstream, err)
	}
	defer upConn.Close()
	tc := upConn.(*net.TCPConn)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := io.Copy(stream, tc)
		if err != nil && err != io.EOF && !errors.Is(err, io.ErrClosedPipe) {
			log.Printf("stream %08x:%d stream←upstream: %v", conv, stream.ID(), err)
		}
		tc.CloseRead()
		stream.Close()
	}()
	go func() {
		defer wg.Done()
		_, err := io.Copy(tc, stream)
		if err != nil && err != io.EOF && !errors.Is(err, io.ErrClosedPipe) {
			log.Printf("stream %08x:%d upstream←stream: %v", conv, stream.ID(), err)
		}
		tc.CloseWrite()
	}()
	wg.Wait()
	return nil
}

func acceptStreams(conn *kcp.UDPSession, privkey []byte, upstream string) error {
	log.Printf("session %08x: noise handshake start", conn.GetConv())
	rw, err := noise.NewServer(conn, privkey)
	if err != nil {
		log.Printf("session %08x: noise handshake error: %v", conn.GetConv(), err)
		return err
	}
	log.Printf("session %08x: noise handshake done", conn.GetConv())
	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = 2
	smuxConfig.KeepAliveTimeout = idleTimeout
	smuxConfig.MaxStreamBuffer = 1 * 1024 * 1024
	sess, err := smux.Server(rw, smuxConfig)
	if err != nil {
		return err
	}
	defer sess.Close()
	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			if nerr, ok := err.(net.Error); ok && nerr.Temporary() {
				continue
			}
			return err
		}
		log.Printf("stream %08x:%d open", conn.GetConv(), stream.ID())
		go func() {
			defer func() {
				log.Printf("stream %08x:%d close", conn.GetConv(), stream.ID())
				stream.Close()
			}()
			if err := handleStream(stream, upstream, conn.GetConv()); err != nil {
				log.Printf("stream %08x:%d: %v", conn.GetConv(), stream.ID(), err)
			}
		}()
	}
}

func acceptSessions(ln *kcp.Listener, privkey []byte, mtu int, upstream string) error {
	for {
		conn, err := ln.AcceptKCP()
		if err != nil {
			if nerr, ok := err.(net.Error); ok && nerr.Temporary() {
				continue
			}
			return err
		}
		log.Printf("KCP session %08x open", conn.GetConv())
		conn.SetStreamMode(true)
		conn.SetNoDelay(0, 0, 0, 1)
		conn.SetWindowSize(turbotunnel.QueueSize/2, turbotunnel.QueueSize/2)
		if !conn.SetMtu(mtu) {
			log.Printf("warning: SetMtu(%d) failed", mtu)
		}
		go func() {
			defer func() {
				log.Printf("KCP session %08x close", conn.GetConv())
				conn.Close()
			}()
			if err := acceptStreams(conn, privkey, upstream); err != nil && !errors.Is(err, io.ErrClosedPipe) {
				log.Printf("session %08x: %v", conn.GetConv(), err)
			}
		}()
	}
}

func run(privkey []byte, domain dns.Name, destIP net.IP, spoofSrcIP net.IP, upstream string, dnsConn net.PacketConn, cfg hybrid.Config) error {
	defer dnsConn.Close()

	mtu := cfg.MaxKCPMTU()
	log.Printf("KCP MTU %d (clientIDLen=%d icmpID=%#x maxLabelLen=%d recordType=%d)", mtu, cfg.ClientIDLen, cfg.IcmpID, cfg.MaxLabelLen, cfg.RecordType)
	log.Printf("server pubkey %x", noise.PubkeyFromPrivkey(privkey))

	ttConn := turbotunnel.NewQueuePacketConn(turbotunnel.DummyAddr{}, idleTimeout*2)
	st, err := hybrid.NewServerTransport(domain, destIP, spoofSrcIP, ttConn, cfg)
	if err != nil {
		return err
	}
	defer st.Close()

	ln, err := kcp.ServeConn(nil, 0, 0, ttConn)
	if err != nil {
		return fmt.Errorf("KCP listener: %v", err)
	}
	defer ln.Close()

	go func() {
		if err := acceptSessions(ln, privkey, mtu, upstream); err != nil {
			log.Printf("acceptSessions: %v", err)
		}
	}()

	return st.RecvLoop(dnsConn)
}

func readKey(filename string) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return noise.ReadKey(f)
}

func generateKeypair(privFile, pubFile string) error {
	privkey, err := noise.GeneratePrivkey()
	if err != nil {
		return err
	}
	pubkey := noise.PubkeyFromPrivkey(privkey)

	write := func(filename string, key []byte, perm os.FileMode) error {
		f, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE|os.O_TRUNC, perm)
		if err != nil {
			return err
		}
		if werr := noise.WriteKey(f, key); werr != nil {
			f.Close()
			return werr
		}
		return f.Close()
	}

	if privFile != "" {
		if err := write(privFile, privkey, 0400); err != nil {
			return err
		}
		fmt.Printf("privkey written to %s\n", privFile)
	} else {
		fmt.Printf("privkey %x\n", privkey)
	}
	if pubFile != "" {
		if err := write(pubFile, pubkey, 0644); err != nil {
			return err
		}
		fmt.Printf("pubkey  written to %s\n", pubFile)
	} else {
		fmt.Printf("pubkey  %x\n", pubkey)
	}
	return nil
}

func main() {
	var genKey bool
	var privFile, pubFile, privkeyHex string
	var udpAddr, destIPStr, spoofSrcStr string
	var verbose bool

	defCfg := hybrid.DefaultConfig()
	var clientIDLen, icmpID, maxLabelLen int
	flag.BoolVar(&genKey, "gen-key", false, "generate a server keypair")
	flag.StringVar(&privFile, "privkey-file", "", "server private key file")
	flag.StringVar(&pubFile, "pubkey-file", "", "server public key file (with -gen-key)")
	flag.StringVar(&privkeyHex, "privkey", "", "server private key (hex)")
	flag.StringVar(&udpAddr, "udp", "", "UDP address to listen for DNS queries (required)")
	flag.StringVar(&destIPStr, "dest-ip", "", "client's public IPv4 address to send downstream traffic to (required)")
	flag.StringVar(&spoofSrcStr, "spoof-src", "", "spoofed source IP for downstream ICMP/UDP (leave empty for normal send)")
	var udpPort int
	var udpSrcPortStr string
	flag.IntVar(&udpPort, "downstream-udp-port", 0, "use UDP downstream instead of ICMP; client listens on this port (must match client, 0=ICMP)")
	flag.StringVar(&udpSrcPortStr, "downstream-udp-src-port", fmt.Sprint(defCfg.UDPSrcPort), "source port for spoofed downstream UDP (number or \"random\")")
	flag.IntVar(&clientIDLen, "client-id-len", defCfg.ClientIDLen, "bytes used as DNS/ICMP session ID (must match client)")
	flag.IntVar(&icmpID, "icmp-id", defCfg.IcmpID, "ICMP Echo identifier for tunnel packets (must match client)")
	flag.IntVar(&maxLabelLen, "max-label-len", defCfg.MaxLabelLen, "max base32 chars per DNS label (must match client)")
	var recordTypeStr string
	flag.StringVar(&recordTypeStr, "record-type", "txt", "DNS query type to accept: txt, cname, a, aaaa, mx, ns, srv (must match client)")
	flag.BoolVar(&verbose, "verbose", false, "enable per-packet diagnostic logging")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage:\n  %s -gen-key [-privkey-file FILE] [-pubkey-file FILE]\n  %s -udp ADDR -dest-ip IP [-privkey-file FILE] [-spoof-src IP] DOMAIN UPSTREAMADDR\n\n", os.Args[0], os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.LUTC)

	if genKey {
		if err := generateKeypair(privFile, pubFile); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	if flag.NArg() != 2 {
		flag.Usage()
		os.Exit(1)
	}
	domain, err := dns.ParseName(flag.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid domain: %v\n", err)
		os.Exit(1)
	}
	upstream := flag.Arg(1)

	if destIPStr == "" {
		fmt.Fprintln(os.Stderr, "-dest-ip required")
		os.Exit(1)
	}
	destIP := net.ParseIP(destIPStr)
	if destIP == nil || destIP.To4() == nil {
		fmt.Fprintf(os.Stderr, "invalid -dest-ip: %q (must be IPv4)\n", destIPStr)
		os.Exit(1)
	}

	var spoofSrcIP net.IP
	if spoofSrcStr != "" {
		spoofSrcIP = net.ParseIP(spoofSrcStr)
		if spoofSrcIP == nil {
			fmt.Fprintf(os.Stderr, "invalid -spoof-src: %q\n", spoofSrcStr)
			os.Exit(1)
		}
	}

	var privkey []byte
	switch {
	case privFile != "" && privkeyHex != "":
		fmt.Fprintln(os.Stderr, "only one of -privkey and -privkey-file allowed")
		os.Exit(1)
	case privFile != "":
		privkey, err = readKey(privFile)
	case privkeyHex != "":
		privkey, err = noise.DecodeKey(privkeyHex)
	default:
		log.Println("no private key provided — generating temporary keypair")
		privkey, err = noise.GeneratePrivkey()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if udpAddr == "" {
		fmt.Fprintln(os.Stderr, "-udp required")
		os.Exit(1)
	}
	dnsConn, err := net.ListenPacket("udp", udpAddr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	recordType, err := hybrid.ParseRecordType(recordTypeStr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var udpSrcPort int // 0 = random
	if udpSrcPortStr != "random" {
		udpSrcPort, err = strconv.Atoi(udpSrcPortStr)
		if err != nil || udpSrcPort < 1 || udpSrcPort > 65535 {
			fmt.Fprintf(os.Stderr, "-downstream-udp-src-port: expected 1-65535 or \"random\", got %q\n", udpSrcPortStr)
			os.Exit(1)
		}
	}
	cfg := hybrid.Config{
		ClientIDLen: clientIDLen,
		IcmpID:      icmpID,
		MaxLabelLen: maxLabelLen,
		RecordType:  recordType,
		UDPPort:     udpPort,
		UDPSrcPort:  udpSrcPort,
		Verbose:     verbose,
	}
	if err := run(privkey, domain, destIP, spoofSrcIP, upstream, dnsConn, cfg); err != nil {
		log.Fatal(err)
	}
}
