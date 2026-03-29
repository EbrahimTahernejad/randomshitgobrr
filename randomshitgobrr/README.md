# randomshitgobrr

A hybrid DNS+ICMP/UDP tunnel using KCP for reliable transport.

**Upstream (client → server):** DNS TXT queries encoded in the VayDNS single-label wire format — each query fits in one DNS label so it passes through resolvers that strip multi-label prefixes. Multiple resolvers can be specified for round-robin or redundant sending.

**Downstream (server → client):** Either ICMP Echo Requests or raw spoofed UDP packets, both with optional spoofed source IP. ICMP exploits the fact that outside→inside ICMP is often unrestricted. UDP can pass through firewalls that block ICMP and requires no raw socket on the client.

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

```bash
./bin/hybrid-server \
  -udp :53 \
  -dest-ip <CLIENT_PUBLIC_IP> \
  -privkey-file server.key \
  [-spoof-src <SPOOF_IP>] \
  t.example.com \
  127.0.0.1:8000
```

| Flag | Required | Description |
|------|----------|-------------|
| `-udp` | yes | UDP address to listen for DNS queries |
| `-dest-ip` | yes | Client's public IPv4 — where to send downstream traffic |
| `-privkey-file` | recommended | Private key file (omit to generate a temporary key) |
| `-spoof-src` | no | Source IP to spoof in downstream ICMP/UDP packets. Omit for normal send. |
| `-downstream-udp-port` | no | Switch downstream from ICMP to raw UDP; client listens on this port. **Must match client.** Default: `0` (ICMP). |
| `-downstream-udp-src-port` | no | Source port for spoofed downstream UDP packets. Number or `random`. Default: `random`. |
| `-client-id-len` | no | Bytes used as session ID. Default: `2`. **Must match client.** |
| `-icmp-id` | no | ICMP Echo identifier. Default: `0x5350`. **Must match client.** |
| `-max-label-len` | no | Max base32 chars per DNS label. Default: `63`. **Must match client.** |
| `-record-type` | no | DNS query type: `txt`, `cname`, `a`, `aaaa`, `mx`, `ns`, `srv`. Default: `txt`. **Must match client.** |
| `DOMAIN` | yes | Tunnel domain (must match NS delegation) |
| `UPSTREAM` | yes | TCP address to forward tunneled connections to |

**ICMP mode only — suppress kernel ICMP auto-replies:**

```bash
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all
# permanent:
echo "net.ipv4.icmp_echo_ignore_all = 1" >> /etc/sysctl.conf && sysctl -p
```

---

### 4. Run the client

```bash
./bin/hybrid-client \
  -udp 8.8.8.8:53 \
  -pubkey-file server.pub \
  t.example.com \
  127.0.0.1:7000
```

**Multiple resolvers (round-robin):**

```bash
./bin/hybrid-client \
  -udp 8.8.8.8:53 -udp 1.1.1.1:53 -udp 9.9.9.9:53 \
  -broadcast 2 \
  -pubkey-file server.pub \
  t.example.com \
  127.0.0.1:7000
```

| Flag | Required | Description |
|------|----------|-------------|
| `-udp` | one of three | UDP DNS resolver (repeatable for round-robin, e.g. `-udp 8.8.8.8:53 -udp 1.1.1.1:53`) |
| `-doh` | one of three | DNS-over-HTTPS resolver URL |
| `-dot` | one of three | DNS-over-TLS resolver address |
| `-broadcast` | no | Number of resolvers to send each packet to. `1` = strict round-robin. Default: `1`. |
| `-pubkey-file` | yes | Server public key file |
| `-downstream-udp-port` | no | Listen on this UDP port for downstream from server (instead of ICMP). **Must match server.** Default: `0` (ICMP). |
| `-client-id-len` | no | Bytes used as session ID. Default: `2`. **Must match server.** |
| `-icmp-id` | no | ICMP Echo identifier. Default: `0x5350`. **Must match server.** |
| `-max-label-len` | no | Max base32 chars per DNS label. Default: `63`. **Must match server.** |
| `-record-type` | no | DNS query type. Default: `txt`. **Must match server.** |
| `DOMAIN` | yes | Tunnel domain (must match server) |
| `LOCALADDR` | yes | Local TCP address to listen on — connect your app here |

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
2. **DNS workers** — concurrently send NS and A queries to each IP; those that answer both are forwarded to the handshake stage
3. **Handshake workers** — run a full Noise handshake through each qualifying IP as a DNS relay and record the latency

Stages 2 and 3 run simultaneously — while handshake workers are blocked waiting for KCP round-trips, DNS workers keep qualifying new IPs in the background.

```bash
hybrid-scanner \
  -list ranges.txt \
  -sample 500 \
  -ns example.com \
  -a example.com \
  -domain t.example.com \
  -pubkey-file server.pub \
  -dns-workers 200 \
  -hs-workers 50 \
  -timeout 8s \
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
| `-ns` | — | Domain for NS query check (required) |
| `-a` | — | Domain for A query check (required) |
| `-domain` | — | Tunnel domain for handshake (required) |
| `-pubkey-file` / `-pubkey` | — | Server public key |
| `-dns-workers` | `200` | Concurrent NS+A check workers (stage 2) |
| `-hs-workers` | `50` | Concurrent Noise handshake workers (stage 3) |
| `-timeout` | `10s` | Per-IP timeout (DNS checks and handshake) |
| `-dns-port` | `53` | DNS port on scanned IPs |
| `-output` | `results.csv` | Output file |
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
Client                                    Server
────────────────────────────────────────────────────────────────
App → TCP
      └→ SMUX stream
           └→ Noise NK (encrypted)
                └→ KCP (reliable, MTU=36)
                     └→ DNS TXT query          ──────────────→  UDP :53
                        [clientID:2][len:1][data]                     ↓
                        one 63-char base32 label              Decode VayDNS format
                        per KCP segment                       Feed KCP segment
                        (round-robin / broadcast                      ↓
                         across multiple resolvers)           KCP → Noise → SMUX → TCP → Upstream

          ICMP mode:
          ←── ICMP Echo Request (optional spoofed src)  ←─ Raw socket
              [clientID:2][uint16-len][KCP]...
              multiple KCP segments bundled per datagram

          UDP mode:
          ←── Raw IP+UDP (spoofed src IP+port)          ←─ Raw socket
              [clientID:2][uint16-len][KCP]...
              same bundling, no CAP_NET_RAW on client
```

---

## License

MIT — see [LICENSE](LICENSE).

Third-party components retain their original licenses (see `../vaydns` and `../spoof-tunnel`).
