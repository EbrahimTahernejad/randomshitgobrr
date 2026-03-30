# randomshitgobrr

A hybrid DNS+ICMP/UDP tunnel using KCP for reliable transport.

**Upstream (client → server):** Two modes — choose based on what the network allows:
- **DNS mode:** TXT queries encoded in VayDNS single-label wire format, sent via a DNS resolver (UDP, DoH, or DoT). Multiple resolvers supported for round-robin or redundant sending.
- **SOCKS mode:** Raw KCP frames over a TCP connection through a SOCKS5 proxy to a server TCP port. No DNS required. Useful when a SOCKS proxy is available but DNS is filtered.

**Downstream (server → client):** Either ICMP Echo Requests or raw spoofed UDP packets (both modes). ICMP exploits the fact that outside→inside ICMP is often unrestricted. UDP can pass through firewalls that block ICMP and requires no raw socket on the client.

Stack: KCP → Noise NK (encryption) → SMUX (multiplexing) → TCP

---

## Credits

This project is built on top of existing tools:

- **[VayDNS](https://github.com/net2share/vaydns)** by net2share — DNS tunnel using KCP, Noise NK, SMUX, and the `[clientID:N][datalen:1][data]` single-label wire format. The protocol structure, Noise layer, SMUX integration, DNS and turbotunnel packages all come from VayDNS. Licensed under the MIT License.

- **[spoof-tunnel](https://github.com/ParsaKSH/spoof-tunnel)** by ParsaKSH — ICMP tunnel with IP source spoofing via raw sockets. The raw socket send approach and gopacket-based packet construction are adapted from spoof-tunnel. Licensed under the MIT License.

---

## Requirements

- Both sides: **root** or `CAP_NET_RAW` (ICMP mode) — UDP mode only requires root on the **server**
- Server: port 53 UDP, a domain with NS record pointing to the server
- Go 1.21+ (to build from source)

---

## Setup

### 1. DNS delegation

Point a subdomain's NS record at your server. In your DNS registrar or authoritative DNS:

```
t.example.com.   IN  NS  ns1.example.com.
ns1.example.com. IN  A   <SERVER_PUBLIC_IP>
```

Replace `t.example.com` with your tunnel domain and `<SERVER_PUBLIC_IP>` with your server's IP.

---

### 2. Generate a keypair (on the server)

```bash
./bin/hybrid-server -gen-key -privkey-file server.key -pubkey-file server.pub
```

Copy `server.pub` to the client machine.

---

### 3. Run the server

**DNS uplink only:**

```bash
./bin/hybrid-server \
  -udp :53 \
  -dest-ip <CLIENT_PUBLIC_IP> \
  -privkey-file server.key \
  t.example.com \
  127.0.0.1:8000
```

**SOCKS uplink only:**

```bash
./bin/hybrid-server \
  -tcp :443 \
  -dest-ip <CLIENT_PUBLIC_IP> \
  -privkey-file server.key \
  127.0.0.1:8000
```

**Both simultaneously (clients can use either):**

```bash
./bin/hybrid-server \
  -udp :53 -tcp :443 \
  -dest-ip <CLIENT_PUBLIC_IP> \
  -privkey-file server.key \
  t.example.com \
  127.0.0.1:8000
```

| Flag | Required | Description |
|------|----------|-------------|
| `-udp` | one of two | UDP address to listen for DNS-uplink clients |
| `-tcp` | one of two | TCP address to listen for SOCKS-uplink clients |
| `-dest-ip` | yes | Client's public IPv4 — where to send downstream traffic |
| `-privkey-file` | recommended | Private key file (omit to generate a temporary key) |
| `-privkey` | no (alt) | Private key as hex string |
| `-spoof-src` | no | Source IP to spoof in downstream ICMP/UDP packets. Omit for normal send. |
| `-downstream-udp-port` | no | Switch downstream from ICMP to raw UDP; client listens on this port. **Must match client.** Default: `0` (ICMP). |
| `-downstream-udp-src-port` | no | Source port for spoofed downstream UDP packets. Number or `random`. Default: `random`. |
| `-client-id-len` | no | Bytes used as session ID. Default: `2`. **Must match client.** |
| `-icmp-id` | no | ICMP Echo identifier. Default: `0x5350`. **Must match client.** |
| `-max-label-len` | no | Max base32 chars per DNS label. Default: `63`. **DNS mode only. Must match client.** |
| `-record-type` | no | DNS query type: `txt`, `cname`, `a`, `aaaa`, `mx`, `ns`, `srv`. Default: `txt`. **DNS mode only. Must match client.** |
| `-verbose` | no | Enable per-packet diagnostic logging. |
| `DOMAIN UPSTREAM` | with `-udp` | Tunnel domain then TCP forward address |
| `UPSTREAM` | `-tcp` only | TCP address to forward tunneled connections to |

**ICMP mode only — suppress kernel ICMP auto-replies:**

```bash
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all
# permanent:
echo "net.ipv4.icmp_echo_ignore_all = 1" >> /etc/sysctl.conf && sysctl -p
```

---

### 4. Run the client

**DNS uplink (through a DNS resolver):**

```bash
./bin/hybrid-client \
  -udp 8.8.8.8:53 \
  -pubkey-file server.pub \
  t.example.com \
  127.0.0.1:7000
```

**DNS uplink — multiple resolvers (round-robin):**

```bash
./bin/hybrid-client \
  -udp 8.8.8.8:53 -udp 1.1.1.1:53 -udp 9.9.9.9:53 \
  -broadcast 2 \
  -pubkey-file server.pub \
  t.example.com \
  127.0.0.1:7000
```

**SOCKS uplink (TCP through a SOCKS5 proxy):**

```bash
./bin/hybrid-client \
  -socks5 proxy.corp:1080 \
  -tcp-server SERVER_IP:443 \
  -pubkey-file server.pub \
  127.0.0.1:7000
```

| Flag | Required | Description |
|------|----------|-------------|
| `-udp` | one of four | UDP DNS resolver (repeatable for round-robin) |
| `-doh` | one of four | DNS-over-HTTPS resolver URL |
| `-dot` | one of four | DNS-over-TLS resolver address |
| `-socks5` | one of four | SOCKS5 proxy address for TCP uplink (`host:port`) |
| `-tcp-server` | with `-socks5` | Server TCP address to connect to through the proxy (`host:port`) |
| `-broadcast` | no | Number of resolvers to send each packet to. `1` = strict round-robin. Default: `1`. |
| `-pubkey-file` | yes | Server public key file |
| `-pubkey` | yes (alt) | Server public key as hex string |
| `-downstream-udp-port` | no | Listen on this UDP port for downstream from server (instead of ICMP). **Must match server.** Default: `0` (ICMP). |
| `-client-id-len` | no | Bytes used as session ID. Default: `2`. **Must match server.** |
| `-icmp-id` | no | ICMP Echo identifier. Default: `0x5350`. **Must match server.** |
| `-max-label-len` | no | Max base32 chars per DNS label. **DNS mode only.** **Must match server.** |
| `-record-type` | no | DNS query type. **DNS mode only.** **Must match server.** |
| `-verbose` | no | Enable per-packet diagnostic logging. |
| `DOMAIN LOCALADDR` | DNS mode | Tunnel domain then local listen address |
| `LOCALADDR` | SOCKS mode | Local TCP address to listen on |

---

## Downstream modes

### ICMP (default)

The server sends KCP segments as ICMP Echo Requests to `-dest-ip`. The client reads them via a raw ICMP socket (requires `CAP_NET_RAW` on client).

### UDP (`-downstream-udp-port`)

The server builds raw IP+UDP packets with a spoofed source address and sends them to `<CLIENT_IP>:<downstream-udp-port>`. The client binds a plain UDP socket on that port — **no raw socket privilege needed on the client**.

The source port defaults to `random` (a fresh ephemeral port per packet) but can be fixed to a specific port (e.g. `53` to look like a DNS response) with `-downstream-udp-src-port 53`.

```bash
# server
hybrid-server -udp :53 -dest-ip 1.2.3.4 -spoof-src 5.6.7.8 \
  -downstream-udp-port 5555 \
  -privkey-file server.key t.example.com 127.0.0.1:8000

# client (no CAP_NET_RAW required)
hybrid-client -udp 5.6.7.8:53 -downstream-udp-port 5555 \
  -pubkey-file server.pub t.example.com 127.0.0.1:7000
```

---

## Wire-protocol flags

The flags `-client-id-len`, `-icmp-id`, `-max-label-len`, `-record-type`, and `-downstream-udp-port` must be **identical on both sides**. Mismatches cause silent failures:

| Flag | Mismatch effect |
|------|----------------|
| `-client-id-len` | Server reads wrong prefix length from DNS; downstream filter fails on client |
| `-icmp-id` | Client ignores all downstream ICMP (ID mismatch) |
| `-max-label-len` | Client truncates queries at a different boundary than server decodes |
| `-record-type` | Server returns NXDOMAIN for every query; tunnel never establishes |
| `-downstream-udp-port` | Server sends UDP to wrong port or client listens on wrong port |

The KCP MTU is derived automatically: `floor(max-label-len × 5/8) − client-id-len − 1`. With defaults this is **36 bytes** per segment, which base32-encodes to exactly 63 characters — one DNS label.

---

## Using the tunnel

Once the client is running, connect your application to the local address:

```bash
# SSH through the tunnel (if upstream is an SSH server)
ssh user@127.0.0.1 -p 7000

# SOCKS proxy (if upstream is a SOCKS server)
curl --socks5 127.0.0.1:7000 https://example.com
```

The client accepts TCP connections on `LOCALADDR` and forwards them through the tunnel to the server's upstream address.

---

## Scanner

`hybrid-scanner` finds working DNS resolvers for the tunnel by probing IPs from a list. It runs as a three-stage pipeline:

1. **Sampler** — reads IPs/CIDRs, reservoir-samples N, feeds into the DNS stage
2. **DNS workers** — concurrently send an A query to each IP; those that respond with NOERROR are forwarded to the handshake stage
3. **Handshake workers** — run a full Noise handshake through each qualifying IP as a DNS relay and record the latency

Stages 2 and 3 run simultaneously — while handshake workers are blocked waiting for KCP round-trips, DNS workers keep qualifying new IPs in the background.

```bash
hybrid-scanner \
  -list ranges.txt \
  -sample 500 \
  -a example.com \
  -domain t.example.com \
  -pubkey-file server.pub \
  -dns-workers 200 \
  -hs-workers 50 \
  -dns-timeout 3s \
  -hs-timeout 10s \
  -output results.csv
```

`ranges.txt` accepts CIDRs and individual IPs (lines starting with `#` are ignored):

```
8.8.8.0/24
1.1.1.1
9.9.9.0/28
```

| Flag | Default | Description |
|------|---------|-------------|
| `-list` | — | IP/CIDR list file (required) |
| `-sample` | `100` | IPs to randomly sample |
| `-a` | — | Domain for A query check (required) |
| `-domain` | — | Tunnel domain for handshake (required) |
| `-pubkey-file` / `-pubkey` | — | Server public key |
| `-dns-workers` | `200` | Concurrent A-query workers (stage 2) |
| `-hs-workers` | `50` | Concurrent Noise handshake workers (stage 3) |
| `-dns-timeout` | `3s` | Timeout for A query check |
| `-hs-timeout` | `10s` | Timeout for Noise handshake |
| `-dns-port` | `53` | DNS port on scanned IPs |
| `-output` | `results.csv` | Output file |
| `-client-id-len` | `2` | Session ID length. **Must match server.** |
| `-icmp-id` | `0x5350` | ICMP Echo identifier. **Must match server.** |
| `-max-label-len` | `63` | Max base32 chars per DNS label. **Must match server.** |
| `-record-type` | `txt` | DNS query type. **Must match server.** |

Output format: `ip,latency_ms`

Requires root/`CAP_NET_RAW` (opens a raw ICMP socket per handshake worker).

The scanner has a live terminal UI showing stage progress bars, pass/fail counters, a scrolling results feed, and elapsed time.

---

## Building from source

```bash
git clone --recurse-submodules <repo>
cd randomshitgobrr/randomshitgobrr
go build -o bin/hybrid-server  ./cmd/server
go build -o bin/hybrid-client  ./cmd/client
go build -o bin/hybrid-scanner ./cmd/scanner
```

If you cloned without `--recurse-submodules`:

```bash
git submodule update --init
```

---

## How it works

```
Client                                         Server
──────────────────────────────────────────────────────────────────────
App → TCP
      └→ SMUX stream
           └→ Noise NK (encrypted)
                └→ KCP (reliable)

  DNS uplink (MTU=36):                         UDP :53
  KCP segment → DNS TXT query  ─────────────→  Decode VayDNS format
    [clientID:2][len:1][data]                   Feed KCP segment
    base32 label, round-robin                        ↓
    across resolvers             KCP → Noise → SMUX → TCP → Upstream

  SOCKS uplink (MTU=1400):                     TCP :PORT
  KCP segment → TCP frame      ─────────────→  Read length-prefixed frames
    [uint16-len][data]                          Feed KCP segment
    via SOCKS5 proxy → server                        ↓
                                 KCP → Noise → SMUX → TCP → Upstream

  Downstream — ICMP mode (both uplink types):
  ←── ICMP Echo Request (optional spoofed src)  ←─ Raw socket
      [clientID:2][uint16-len][KCP]...
      multiple KCP segments bundled per datagram

  Downstream — UDP mode (both uplink types):
  ←── Raw IP+UDP (spoofed src IP+port)          ←─ Raw socket
      [clientID:2][uint16-len][KCP]...
      same bundling, no CAP_NET_RAW on client
```

---

## License

MIT — see [LICENSE](LICENSE).

Third-party components retain their original licenses (see `../vaydns` and `../spoof-tunnel`).
