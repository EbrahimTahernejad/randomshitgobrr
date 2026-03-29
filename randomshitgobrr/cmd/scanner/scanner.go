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

	"golang.org/x/net/dns/dnsmessage"

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

// dnsCheckA sends a DNS A query to resolverIP:port using the standard
// golang.org/x/net/dns/dnsmessage package (handles name compression correctly)
// and returns true if the response is NOERROR with at least one A record.
func dnsCheckA(resolverIP string, port int, name string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("udp", net.JoinHostPort(resolverIP, fmt.Sprint(port)), timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout)) //nolint:errcheck

	fqdn := name
	if !strings.HasSuffix(fqdn, ".") {
		fqdn += "."
	}
	qname, err := dnsmessage.NewName(fqdn)
	if err != nil {
		return false
	}

	var buf [512]byte
	b := dnsmessage.NewBuilder(buf[:0], dnsmessage.Header{
		ID:               uint16(rand.Uint32()),
		RecursionDesired: true,
	})
	b.StartQuestions() //nolint:errcheck
	b.Question(dnsmessage.Question{ //nolint:errcheck
		Name:  qname,
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	})
	msg, err := b.Finish()
	if err != nil {
		return false
	}

	if _, err := conn.Write(msg); err != nil {
		return false
	}
	var resp [4096]byte
	n, err := conn.Read(resp[:])
	if err != nil {
		return false
	}

	var p dnsmessage.Parser
	hdr, err := p.Start(resp[:n])
	if err != nil {
		return false
	}
	if hdr.RCode != dnsmessage.RCodeSuccess {
		return false
	}
	p.SkipAllQuestions() //nolint:errcheck
	for {
		ah, err := p.AnswerHeader()
		if err != nil {
			return false // ErrSectionDone or parse error — no A record found
		}
		if ah.Type == dnsmessage.TypeA {
			return true
		}
		p.SkipAnswer() //nolint:errcheck
	}
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
