package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
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

// runScanner executes the three-stage pipeline and writes results to out.
// It updates stats as work progresses and calls stats.markDone() when finished.
func runScanner(
	ips []net.IP,
	dnsPort int,
	nsDomain, aDomain, tunnelDomain dns.Name,
	pubkey []byte,
	cfg hybrid.Config,
	dnsWorkers, hsWorkers int,
	timeout time.Duration,
	out io.Writer,
	stats *scanStats,
) {
	var outMu sync.Mutex

	// stage 1 → stage 2
	ipChan := make(chan net.IP, dnsWorkers)
	// stage 2 → stage 3
	qualifiedChan := make(chan net.IP, hsWorkers)

	// stage 1: feed IPs
	go func() {
		for _, ip := range ips {
			ipChan <- ip
		}
		close(ipChan)
	}()

	// stage 2: DNS checks
	var dnsWG sync.WaitGroup
	for i := 0; i < dnsWorkers; i++ {
		dnsWG.Add(1)
		go func() {
			defer dnsWG.Done()
			for ip := range ipChan {
				ok := dnsCheck2(ip.String(), dnsPort, nsDomain, aDomain, timeout)
				stats.recordDNS(ok)
				if ok {
					qualifiedChan <- ip
				}
			}
		}()
	}
	go func() {
		dnsWG.Wait()
		close(qualifiedChan)
	}()

	// stage 3: handshake
	var hsWG sync.WaitGroup
	for i := 0; i < hsWorkers; i++ {
		hsWG.Add(1)
		go func() {
			defer hsWG.Done()
			for ip := range qualifiedChan {
				lat, err := doHandshake(ip, dnsPort, tunnelDomain, pubkey, cfg, timeout)
				passed := err == nil
				stats.recordHS(ip.String(), lat, passed)
				if passed {
					outMu.Lock()
					fmt.Fprintf(out, "%s,%.2f\n", ip, float64(lat.Milliseconds()))
					outMu.Unlock()
				}
			}
		}()
	}
	hsWG.Wait()
	stats.markDone()
}

// dnsCheck2 checks both NS and A queries for ip.
func dnsCheck2(ipStr string, dnsPort int, nsDomain, aDomain dns.Name, timeout time.Duration) bool {
	return dnsCheck(ipStr, dnsPort, nsDomain, hybrid.RRTypeNS, timeout) &&
		dnsCheck(ipStr, dnsPort, aDomain, hybrid.RRTypeA, timeout)
}

// dnsCheck sends one DNS query and returns true on NOERROR + at least one answer.
func dnsCheck(resolverIP string, dnsPort int, name dns.Name, qtype uint16, timeout time.Duration) bool {
	conn, err := net.DialTimeout("udp", net.JoinHostPort(resolverIP, fmt.Sprint(dnsPort)), timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout)) //nolint:errcheck

	var id uint16
	binary.Read(rand.New(rand.NewSource(rand.Int63())), binary.BigEndian, &id) //nolint:errcheck
	query := &dns.Message{
		ID:    id,
		Flags: 0x0100,
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

// doHandshake opens a hybrid ClientConn through ip as the DNS relay and times
// the Noise NK handshake.
func doHandshake(ip net.IP, dnsPort int, tunnelDomain dns.Name, pubkey []byte, cfg hybrid.Config, timeout time.Duration) (time.Duration, error) {
	resolver, err := net.ResolveUDPAddr("udp", net.JoinHostPort(ip.String(), fmt.Sprint(dnsPort)))
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
	kcpConn.SetDeadline(time.Now().Add(timeout)) //nolint:errcheck

	start := time.Now()
	_, err = noise.NewClient(kcpConn, pubkey)
	if err != nil {
		return 0, fmt.Errorf("handshake: %w", err)
	}
	return time.Since(start), nil
}

// loadAndSample reads IPs and CIDR ranges from filename, reservoir-samples up
// to n of them, and returns warnings for any unparseable lines.
// Memory usage is O(n) regardless of list size.
func loadAndSample(filename string, n int) ([]net.IP, []string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	var warnings []string
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
				warnings = append(warnings, fmt.Sprintf("skip %q: %v", line, err))
				continue
			}
		} else {
			ip := net.ParseIP(line)
			if ip == nil {
				warnings = append(warnings, fmt.Sprintf("skip invalid IP %q", line))
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
		return nil, warnings, err
	}
	if len(reservoir) == 0 {
		return nil, warnings, fmt.Errorf("no valid IPs found in %s", filename)
	}

	rand.Shuffle(len(reservoir), func(i, j int) {
		reservoir[i], reservoir[j] = reservoir[j], reservoir[i]
	})
	return reservoir, warnings, nil
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

// suppress unused import warning — log is used by callers in main.go
var _ = log.Printf
