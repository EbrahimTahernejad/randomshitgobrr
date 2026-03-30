package main

import (
	"bufio"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	mdns "github.com/miekg/dns"
	"github.com/user/randomshitgobrr/internal/hybrid"
	"github.com/xtaci/kcp-go/v5"
	"github.com/net2share/vaydns/dns"
	"github.com/net2share/vaydns/noise"
	"github.com/net2share/vaydns/turbotunnel"
)

// runScanner executes the three-stage pipeline and writes results to out.
func runScanner(
	ips []net.IP,
	dnsPort int,
	aDomain string,
	tunnelDomain dns.Name,
	pubkey []byte,
	cfg hybrid.Config,
	dnsWorkers, hsWorkers int,
	dnsTimeout, hsTimeout time.Duration,
	out io.Writer,
	stats *scanStats,
) {
	var outMu sync.Mutex

	ipChan := make(chan net.IP, dnsWorkers)
	qualifiedChan := make(chan net.IP, hsWorkers)

	// stage 1: feed IPs
	go func() {
		for _, ip := range ips {
			ipChan <- ip
		}
		close(ipChan)
	}()

	// stage 2: A query check
	var dnsWG sync.WaitGroup
	for i := 0; i < dnsWorkers; i++ {
		dnsWG.Add(1)
		go func() {
			defer dnsWG.Done()
			for ip := range ipChan {
				ok := dnsCheckA(ip.String(), dnsPort, aDomain, dnsTimeout)
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

	// stage 3: Noise handshake
	var hsWG sync.WaitGroup
	for i := 0; i < hsWorkers; i++ {
		hsWG.Add(1)
		go func() {
			defer hsWG.Done()
			for ip := range qualifiedChan {
				lat, err := doHandshake(ip, dnsPort, tunnelDomain, pubkey, cfg, hsTimeout)
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

// dnsCheckA sends a DNS A query to resolverIP:port and returns true if the
// response is NOERROR with at least one answer record.
//
// Strategy (mirrors findns):
//  1. UDP with EDNS0 (1232-byte buffer)
//  2. If FORMERR/SERVFAIL → retry UDP without EDNS0
//  3. If TC bit set → retry over TCP
//
// The UDP path uses an unconnected socket (ListenUDP + WriteTo/ReadFrom) so
// ICMP port-unreachable errors from intermediate hops are ignored rather than
// surfaced immediately as ECONNREFUSED (connected UDP sockets propagate these).
func dnsCheckA(resolverIP string, port int, name string, timeout time.Duration) bool {
	addr := net.JoinHostPort(resolverIP, fmt.Sprint(port))
	fqdn := mdns.Fqdn(name)

	// 1. UDP with EDNS0
	m := new(mdns.Msg)
	m.SetQuestion(fqdn, mdns.TypeA)
	m.RecursionDesired = true
	m.SetEdns0(1232, false)

	r := udpExchange(m, addr, timeout)

	// 2. EDNS0 strip retry
	if r != nil && (r.Rcode == mdns.RcodeFormatError || r.Rcode == mdns.RcodeServerFailure) {
		m2 := new(mdns.Msg)
		m2.SetQuestion(fqdn, mdns.TypeA)
		m2.RecursionDesired = true
		r = udpExchange(m2, addr, timeout)
	}

	// 3. TCP fallback if truncated
	if r != nil && r.Truncated {
		c := &mdns.Client{Net: "tcp", Timeout: timeout}
		m2 := new(mdns.Msg)
		m2.SetQuestion(fqdn, mdns.TypeA)
		m2.RecursionDesired = true
		if resp, _, err := c.Exchange(m2, addr); err == nil {
			r = resp
		}
	}

	return r != nil && r.Rcode == mdns.RcodeSuccess && len(r.Answer) > 0
}

// udpExchange sends a DNS message over an unconnected UDP socket and returns
// the parsed response, or nil on error/timeout.
func udpExchange(m *mdns.Msg, addr string, timeout time.Duration) *mdns.Msg {
	packed, err := m.Pack()
	if err != nil {
		return nil
	}
	dst, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil
	}
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout)) //nolint:errcheck

	if _, err := conn.WriteTo(packed, dst); err != nil {
		return nil
	}
	var buf [4096]byte
	n, _, err := conn.ReadFrom(buf[:])
	if err != nil {
		return nil
	}
	reply := new(mdns.Msg)
	if err := reply.Unpack(buf[:n]); err != nil {
		return nil
	}
	if reply.Id != m.Id {
		return nil // stray packet
	}
	return reply
}

// doHandshake opens a hybrid ClientConn through ip as DNS relay and times
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

// loadAndSample reads IPs and CIDR ranges, reservoir-samples up to n of them.
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
