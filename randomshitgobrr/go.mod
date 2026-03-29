module github.com/user/randomshitgobrr

go 1.24.0

require (
	github.com/google/gopacket v1.1.19
	github.com/xtaci/kcp-go/v5 v5.6.8
	github.com/xtaci/smux v1.5.24
	golang.org/x/net v0.47.0
	www.bamsoftware.com/git/dnstt.git v0.0.0-00010101000000-000000000000
)

require (
	github.com/flynn/noise v1.0.0 // indirect
	github.com/klauspost/cpuid/v2 v2.2.6 // indirect
	github.com/klauspost/reedsolomon v1.12.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/tjfoc/gmsm v1.4.1 // indirect
	golang.org/x/crypto v0.45.0 // indirect
	golang.org/x/sys v0.38.0 // indirect
	golang.org/x/time v0.14.0 // indirect
)

replace www.bamsoftware.com/git/dnstt.git => ../dnstt

replace github.com/xtaci/kcp-go/v5 => github.com/net2share/kcp-go/v5 v5.0.0-20260325165956-416ba9d3856d
