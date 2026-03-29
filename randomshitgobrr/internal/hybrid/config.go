package hybrid

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
}

// DefaultConfig returns a Config with production-ready defaults.
func DefaultConfig() Config {
	return Config{
		ClientIDLen: 2,
		IcmpID:      0x5350,
		MaxLabelLen: 63,
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
