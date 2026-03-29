// hybrid-scanner probes IPs/CIDRs to find working DNS relays for the tunnel.
//
// Pipeline:
//
//	Stage 1  sampler    → reads list, reservoir-samples N IPs
//	Stage 2  DNS check  → NS+A queries in parallel (fast, many workers)
//	Stage 3  Handshake  → full Noise handshake timing (slower, fewer workers)
//
// Stages 2 and 3 run simultaneously via a channel between them.
//
// Usage:
//
//	hybrid-scanner -list FILE -sample N -ns DOMAIN -a DOMAIN \
//	  -domain TUNNEL_DOMAIN -pubkey-file FILE [flags]
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/net2share/vaydns/dns"
	"github.com/net2share/vaydns/noise"
	"github.com/user/randomshitgobrr/internal/hybrid"
)

func main() {
	var listFile, outputFile string
	var sampleCount, dnsWorkers, hsWorkers, dnsPort int
	var nsDomainStr, aDomainStr, tunnelDomainStr string
	var pubkeyFile, pubkeyHex string
	var timeout time.Duration

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
	flag.IntVar(&dnsWorkers, "dns-workers", 200, "concurrent NS+A check workers (stage 2)")
	flag.IntVar(&hsWorkers, "hs-workers", 50, "concurrent Noise handshake workers (stage 3)")
	flag.DurationVar(&timeout, "timeout", 10*time.Second, "per-IP timeout")
	flag.IntVar(&dnsPort, "dns-port", 53, "DNS port on scanned IPs")
	flag.IntVar(&clientIDLen, "client-id-len", defCfg.ClientIDLen, "session ID length (must match server)")
	flag.IntVar(&icmpID, "icmp-id", defCfg.IcmpID, "ICMP Echo identifier (must match server)")
	flag.IntVar(&maxLabelLen, "max-label-len", defCfg.MaxLabelLen, "max base32 chars per DNS label (must match server)")
	flag.StringVar(&recordTypeStr, "record-type", "txt", "DNS query type (must match server)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr,
			"Usage: %s -list FILE -sample N -ns DOMAIN -a DOMAIN -domain DOMAIN -pubkey-file FILE [flags]\n\n",
			os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

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

	// Load IPs before starting the TUI so warnings can be printed cleanly.
	ips, warnings, err := loadAndSample(listFile, sampleCount)
	if err != nil {
		log.Fatalf("load list: %v", err)
	}
	for _, w := range warnings {
		fmt.Fprintln(os.Stderr, "warn:", w)
	}

	out, err := os.Create(outputFile)
	if err != nil {
		log.Fatal(err)
	}
	defer out.Close()
	fmt.Fprintln(out, "ip,latency_ms")

	cfg := hybrid.Config{
		ClientIDLen: clientIDLen,
		IcmpID:      icmpID,
		MaxLabelLen: maxLabelLen,
		RecordType:  recordType,
		// Verbose false — scanner has its own UI
	}

	stats := &scanStats{}
	uiCfg := uiConfig{
		total:      len(ips),
		listFile:   listFile,
		domain:     tunnelDomainStr,
		dnsWorkers: dnsWorkers,
		hsWorkers:  hsWorkers,
		outputFile: outputFile,
		start:      time.Now(),
	}

	// Start the scanner pipeline in the background.
	go runScanner(ips, dnsPort, nsDomain, aDomain, tunnelDomain, pubkey, cfg,
		dnsWorkers, hsWorkers, timeout, out, stats)

	// Run the TUI without alt screen so the final state stays in the scroll
	// buffer when the program exits.
	p := tea.NewProgram(newModel(uiCfg, stats))
	if _, err := p.Run(); err != nil {
		log.Fatal(err)
	}

	// Print a plain-text summary so it's always visible after the TUI.
	fmt.Printf("\ndns  %d/%d passed    handshake  %d/%d passed    → %s\n",
		stats.dnsPassed.Load(), stats.dnsDone.Load(),
		stats.hsPassed.Load(), stats.hsDone.Load(),
		outputFile,
	)
}
