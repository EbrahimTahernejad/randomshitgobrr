package hybrid

import "fmt"

// Standard DNS QTYPE values used by the tunnel.
const (
	RRTypeTXT   uint16 = 16
	RRTypeCNAME uint16 = 5
	RRTypeA     uint16 = 1
	RRTypeAAAA  uint16 = 28
	RRTypeMX    uint16 = 15
	RRTypeNS    uint16 = 2
	RRTypeSRV   uint16 = 33
)

// recordTypeMap maps lowercase flag strings to DNS QTYPE values.
var recordTypeMap = map[string]uint16{
	"txt":   RRTypeTXT,
	"cname": RRTypeCNAME,
	"a":     RRTypeA,
	"aaaa":  RRTypeAAAA,
	"mx":    RRTypeMX,
	"ns":    RRTypeNS,
	"srv":   RRTypeSRV,
}

// ParseRecordType converts a record-type flag string (e.g. "txt", "cname")
// to the corresponding DNS QTYPE value.
func ParseRecordType(s string) (uint16, error) {
	v, ok := recordTypeMap[s]
	if !ok {
		return 0, fmt.Errorf("unknown record type %q (valid: txt, cname, a, aaaa, mx, ns, srv)", s)
	}
	return v, nil
}

// Config holds wire-protocol parameters that must be identical on both
// the client and the server. Mismatches will silently break the tunnel.
type Config struct {
	// ClientIDLen is the number of bytes used as the DNS/ICMP session
	// identifier. The client sends this many bytes at the front of every
	// DNS query; the server reads the same number to route the session;
	// and both use it as the prefix of every ICMP payload.
	// Default: 2.
	ClientIDLen int

	// IcmpID is the 16-bit ICMP Echo identifier stamped on every
	// downstream datagram. The client ignores ICMP packets whose ID
	// field does not match.
	// Default: 0x5350 ("SP").
	IcmpID int

	// MaxLabelLen is the maximum number of base32-encoded characters
	// allowed in a single DNS label. DNS mandates ≤63; lower values
	// reduce the data capacity but can help with restrictive resolvers.
	// Default: 63.
	MaxLabelLen int

	// RecordType is the DNS QTYPE used for upstream queries.
	// The server only responds to queries of this type; the client stamps
	// this type into every outgoing DNS question.
	// Use ParseRecordType to convert a flag string to this value.
	// Default: RRTypeTXT (16).
	RecordType uint16

	// UDPPort, when non-zero, switches the downstream transport from ICMP to
	// raw spoofed UDP. The client listens on this port; the server sends to it.
	// Must be identical on client and server. 0 = ICMP (default).
	UDPPort int

	// UDPSrcPort is the source port stamped on the server's spoofed UDP
	// packets. Only used when UDPPort > 0. Using a common port (e.g. 53, 443)
	// can help with stateful firewalls that track UDP flows.
	// Default: 53. Only meaningful on the server side.
	UDPSrcPort int

	// Verbose enables per-packet diagnostic logging (DNS sends, ICMP/UDP
	// receives, KCP bundle stats). Disabled by default; enable with -verbose.
	Verbose bool
}

// DefaultConfig returns a Config with production-ready defaults.
func DefaultConfig() Config {
	return Config{
		ClientIDLen: 2,
		IcmpID:      0x5350,
		MaxLabelLen: 63,
		RecordType:  RRTypeTXT,
		UDPSrcPort:  53,
	}
}

// MaxKCPMTU returns the maximum KCP MTU that fits within a single DNS label
// using the VayDNS wire format for this config.
//
//	raw_bytes  = floor(MaxLabelLen * 5 / 8)   // base32 decode
//	overhead   = ClientIDLen + 1              // [clientID][datalen]
//	KCP MTU    = raw_bytes - overhead
func (c Config) MaxKCPMTU() int {
	raw := c.MaxLabelLen * 5 / 8
	return raw - c.ClientIDLen - 1
}
