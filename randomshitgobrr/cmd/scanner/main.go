// hybrid-scanner probes a list of IPs/CIDRs to find ones that work as DNS
// relays for the hybrid tunnel. Two stages run in parallel:
//
//   - Stage 1: reads IPs/CIDRs from a file, samples N of them, feeds into a channel.
//   - Stage 2: workers pull IPs from the channel, check NS+A DNS responses,
//     then time a full Noise handshake through the IP as a resolver.
//
// IPs that pass both checks are written to the output file with their handshake latency.
//
// Usage:
//
//	hybrid-scanner -list FILE -sample N -ns DOMAIN -a DOMAIN \
//	  -domain TUNNEL_DOMAIN -pubkey-file FILE [flags]
package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/user/randomshitgobrr/internal/hybrid"
	"github.com/xtaci/kcp-go/v5"
	"github.com/net2share/vaydns/dns"
	"github.com/net2share/vaydns/noise"
	"github.com/net2share/vaydns/turbotunnel"
)

func main() {
	var listFile, outputFile string
	var sampleCount, workers, dnsPort int
	var nsDomainStr, aDomainStr, tunnelDomainStr string
	var pubkeyFile, pubkeyHex string
	var timeout time.Duration
	var verbose bool

	defCfg := hybrid.DefaultConfig()
	var clientIDLen, icmpID, maxLabelLen int
	var recordTypeStr string

	flag.StringVar(&listFile, "list", "", "file with IPs and CIDR ranges, one per line (required)")
	flag.IntVar(&sampleCount, "sample", 100, "number of IPs to randomly sample from the list")
	flag.StringVar(&nsDomainStr, "ns", "", "domain for NS query check (required)")
	flag.StringVar(&aDomainStr, "a", "", "domain for A query check (required)")
	flag.StringVar(&tunnelDomainStr, "domain", "", "tunnel domain for Noise handshake (required)")
	flag.StringVar(&pubkeyFile, "pubkey-file", "", "server public key file")
	flag.StringVar(&pubkeyHex, "pubkey", "", fmt.Sprintf("server public key (%d hex digits)", noise.KeyLen*2))
	flag.StringVar(&outputFile, "output", "results.csv", "output file (CSV: ip,latency_ms)")
	flag.IntVar(&workers, "workers", 50, "concurrent scan workers")
	flag.DurationVar(&timeout, "timeout", 10*time.Second, "per-IP timeout for DNS checks and handshake")
	flag.IntVar(&dnsPort, "dns-port", 53, "DNS port on scanned IPs")
	flag.IntVar(&clientIDLen, "client-id-len", defCfg.ClientIDLen, "session ID length (must match server)")
	flag.IntVar(&icmpID, "icmp-id", defCfg.IcmpID, "ICMP Echo identifier (must match server)")
	flag.IntVar(&maxLabelLen, "max-label-len", defCfg.MaxLabelLen, "max base32 chars per DNS label (must match server)")
	flag.StringVar(&recordTypeStr, "record-type", "txt", "DNS query type (must match server)")
	flag.BoolVar(&verbose, "verbose", false, "log every probe attempt")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s -list FILE -sample N -ns DOMAIN -a DOMAIN -domain DOMAIN -pubkey-file FILE [flags]\n\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.LUTC)

	if listFile == "" || nsDomainStr == "" || aDomainStr == "" || tunnelDomainStr == "" {
		flag.Usage()
		os.Exit(1)
	}
	if pubkeyFile == "" && pubkeyHex == "" {
		fmt.Fprintln(os.Stderr, "-pubkey-file or -pubkey required")
		os.Exit(1)
	}

	nsDomain, err := dns.ParseName(nsDomainStr)
	if err != nil {
		log.Fatalf("invalid -ns: %v", err)
	}
	aDomain, err := dns.ParseName(aDomainStr)
	if err != nil {
		log.Fatalf("invalid -a: %v", err)
	}
	tunnelDomain, err := dns.ParseName(tunnelDomainStr)
	if err != nil {
		log.Fatalf("invalid -domain: %v", err)
	}

	var pubkey []byte
	switch {
	case pubkeyFile != "" && pubkeyHex != "":
		log.Fatal("only one of -pubkey and -pubkey-file allowed")
	case pubkeyFile != "":
		f, err := os.Open(pubkeyFile)
		if err != nil {
			log.Fatal(err)
		}
		pubkey, err = noise.ReadKey(f)
		f.Close()
		if err != nil {
			log.Fatal(err)
		}
	case pubkeyHex != "":
		pubkey, err = noise.DecodeKey(pubkeyHex)
		if err != nil {
			log.Fatal(err)
		}
	}

	recordType, err := hybrid.ParseRecordType(recordTypeStr)
	if err != nil {
		log.Fatal(err)
	}
	cfg := hybrid.Config{
		ClientIDLen: clientIDLen,
		IcmpID:      icmpID,
		MaxLabelLen: maxLabelLen,
		RecordType:  recordType,
		// Verbose intentionally false — scanner logs its own results
	}

	ips, err := loadAndSample(listFile, sampleCount)
	if err != nil {
		log.Fatalf("load list: %v", err)
	}
	log.Printf("sampled %d IPs", len(ips))

	out, err := os.Create(outputFile)
	if err != nil {
		log.Fatal(err)
	}
	defer out.Close()
	fmt.Fprintln(out, "ip,latency_ms")

	var mu sync.Mutex
	passed, failed := 0, 0

	// Stage 1: feed sampled IPs into channel as fast as workers consume them.
	ipChan := make(chan net.IP, workers)
	go func() {
		for _, ip := range ips {
			ipChan <- ip
		}
		close(ipChan)
	}()

	// Stage 2: workers probe each IP in parallel.
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range ipChan {
				lat, err := probeIP(ip, dnsPort, nsDomain, aDomain, tunnelDomain, pubkey, cfg, timeout)
				mu.Lock()
				if err != nil {
					failed++
					if verbose {
						log.Printf("%-15s  FAIL  %v", ip, err)
					}
				} else {
					passed++
					log.Printf("%-15s  OK    %.0f ms", ip, float64(lat.Milliseconds()))
					fmt.Fprintf(out, "%s,%.2f\n", ip, float64(lat.Milliseconds()))
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	log.Printf("done: %d passed, %d failed → %s", passed, failed, outputFile)
}

// probeIP runs the full probe for one IP:
//  1. NS query must return an answer.
//  2. A query must return an answer.
//  3. Noise handshake through the IP as DNS resolver — returns the handshake time.
func probeIP(ip net.IP, dnsPort int, nsDomain, aDomain, tunnelDomain dns.Name, pubkey []byte, cfg hybrid.Config, timeout time.Duration) (time.Duration, error) {
	ipStr := ip.String()

	if !dnsCheck(ipStr, dnsPort, nsDomain, hybrid.RRTypeNS, timeout) {
		return 0, fmt.Errorf("NS query no answer")
	}
	if !dnsCheck(ipStr, dnsPort, aDomain, hybrid.RRTypeA, timeout) {
		return 0, fmt.Errorf("A query no answer")
	}

	resolver, err := net.ResolveUDPAddr("udp", net.JoinHostPort(ipStr, fmt.Sprint(dnsPort)))
	if err != nil {
		return 0, err
	}
	transport, err := net.ListenUDP("udp", nil)
	if err != nil {
		return 0, err
	}

	pconn, err := hybrid.NewClientConn(transport, []net.Addr{resolver}, 1, tunnelDomain, cfg)
	if err != nil {
		transport.Close()
		return 0, fmt.Errorf("client conn: %w", err)
	}
	defer pconn.Close()

	kcpConn, err := kcp.NewConn2(turbotunnel.DummyAddr{}, nil, 0, 0, pconn)
	if err != nil {
		return 0, err
	}
	defer kcpConn.Close()

	kcpConn.SetStreamMode(true)
	kcpConn.SetNoDelay(1, 20, 2, 1)
	kcpConn.SetWindowSize(128, 128)
	kcpConn.SetMtu(cfg.MaxKCPMTU())
	kcpConn.SetDeadline(time.Now().Add(timeout))

	start := time.Now()
	_, err = noise.NewClient(kcpConn, pubkey)
	if err != nil {
		return 0, fmt.Errorf("handshake: %w", err)
	}
	return time.Since(start), nil
}

// dnsCheck sends a single DNS query to resolverIP:dnsPort and returns true if
// the response is NOERROR with at least one answer.
func dnsCheck(resolverIP string, dnsPort int, name dns.Name, qtype uint16, timeout time.Duration) bool {
	conn, err := net.DialTimeout("udp", net.JoinHostPort(resolverIP, fmt.Sprint(dnsPort)), timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	var id uint16
	binary.Read(rand.New(rand.NewSource(rand.Int63())), binary.BigEndian, &id)
	query := &dns.Message{
		ID:    id,
		Flags: 0x0100, // RD
		Question: []dns.Question{
			{Name: name, Type: qtype, Class: dns.ClassIN},
		},
	}
	buf, err := query.WireFormat()
	if err != nil {
		return false
	}
	if _, err := conn.Write(buf); err != nil {
		return false
	}
	resp := make([]byte, 4096)
	n, err := conn.Read(resp)
	if err != nil {
		return false
	}
	msg, err := dns.MessageFromWireFormat(resp[:n])
	if err != nil {
		return false
	}
	return msg.Rcode() == dns.RcodeNoError && len(msg.Answer) > 0
}

// loadAndSample reads IPs and CIDR ranges from filename and reservoir-samples
// up to n of them. Memory usage is O(n) regardless of list size.
func loadAndSample(filename string, n int) ([]net.IP, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	reservoir := make([]net.IP, 0, n)
	total := 0

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		var batch []net.IP
		if strings.Contains(line, "/") {
			batch, err = expandCIDR(line)
			if err != nil {
				log.Printf("skip %q: %v", line, err)
				continue
			}
		} else {
			ip := net.ParseIP(line)
			if ip == nil {
				log.Printf("skip invalid IP %q", line)
				continue
			}
			if ip4 := ip.To4(); ip4 != nil {
				batch = []net.IP{ip4}
			}
		}

		for _, ip := range batch {
			if total < n {
				reservoir = append(reservoir, ip)
			} else {
				j := rand.Intn(total + 1)
				if j < n {
					reservoir[j] = ip
				}
			}
			total++
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(reservoir) == 0 {
		return nil, fmt.Errorf("no valid IPs found in %s", filename)
	}

	rand.Shuffle(len(reservoir), func(i, j int) {
		reservoir[i], reservoir[j] = reservoir[j], reservoir[i]
	})
	return reservoir, nil
}

func expandCIDR(cidr string) ([]net.IP, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	var ips []net.IP
	ip := cloneIP(ipNet.IP.To4())
	for ipNet.Contains(ip) {
		ips = append(ips, cloneIP(ip))
		incrementIP(ip)
	}
	return ips, nil
}

func cloneIP(ip net.IP) net.IP {
	c := make(net.IP, len(ip))
	copy(c, ip)
	return c
}

func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}
