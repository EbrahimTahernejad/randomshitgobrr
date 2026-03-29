# randomshitgobrr

A hybrid DNS+ICMP tunnel using KCP for reliable transport.

**Upstream (client → server):** DNS TXT queries encoded in the VayDNS single-label wire format — each query fits in one DNS label so it passes through resolvers that strip multi-label prefixes.
**Downstream (server → client):** ICMP Echo Requests with optional spoofed source IP — faster than DNS, exploits the fact that outside→inside ICMP is often unrestricted.

Stack: KCP → Noise NK (encryption) → SMUX (multiplexing) → TCP

---

## Credits

This project is built on top of existing tools:

- **[VayDNS](https://github.com/net2share/vaydns)** by net2share — DNS tunnel using KCP, Noise NK, SMUX, and the `[clientID:N][datalen:1][data]` single-label wire format. The protocol structure, Noise layer, SMUX integration, DNS and turbotunnel packages all come from VayDNS. Licensed under the MIT License.

- **[spoof-tunnel](https://github.com/ParsaKSH/spoof-tunnel)** by ParsaKSH — ICMP tunnel with IP source spoofing via raw sockets. The raw socket send approach and gopacket-based packet construction are adapted from spoof-tunnel. Licensed under the MIT License.

---

## Requirements

- Both sides: **root** or `CAP_NET_RAW`
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
| `-dest-ip` | yes | Client's public IPv4 — where to send downstream ICMP |
| `-privkey-file` | recommended | Private key file (omit to generate a temporary key) |
| `-spoof-src` | no | Source IP to spoof in downstream ICMP packets (e.g. `1.1.1.1`). Omit for normal ICMP. |
| `-client-id-len` | no | Bytes used as DNS/ICMP session ID. Default: `2`. **Must match client.** |
| `-icmp-id` | no | ICMP Echo identifier for tunnel packets. Default: `0x5350`. **Must match client.** |
| `-max-label-len` | no | Max base32 chars per DNS label. Default: `63`. **Must match client.** |
| `-record-type` | no | DNS query type to accept: `txt`, `cname`, `a`, `aaaa`, `mx`, `ns`, `srv`. Default: `txt`. **Must match client.** |
| `DOMAIN` | yes | Tunnel domain (must match NS delegation) |
| `UPSTREAM` | yes | TCP address to forward tunneled connections to |

**Suppress kernel ICMP auto-replies** so the OS doesn't respond to the ICMP on behalf of the spoofed source IP:

```bash
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all
```

Make it permanent:

```bash
echo "net.ipv4.icmp_echo_ignore_all = 1" >> /etc/sysctl.conf
sysctl -p
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

| Flag | Required | Description |
|------|----------|-------------|
| `-udp` | one of three | UDP DNS resolver (e.g. `8.8.8.8:53`) |
| `-doh` | one of three | DNS-over-HTTPS resolver URL (e.g. `https://dns.google/dns-query`) |
| `-dot` | one of three | DNS-over-TLS resolver address (e.g. `dns.google:853`) |
| `-pubkey-file` | yes | Server public key file |
| `-client-id-len` | no | Bytes used as DNS/ICMP session ID. Default: `2`. **Must match server.** |
| `-icmp-id` | no | ICMP Echo identifier for tunnel packets. Default: `0x5350`. **Must match server.** |
| `-max-label-len` | no | Max base32 chars per DNS label. Default: `63`. **Must match server.** |
| `-record-type` | no | DNS query type: `txt`, `cname`, `a`, `aaaa`, `mx`, `ns`, `srv`. Default: `txt`. **Must match server.** |
| `DOMAIN` | yes | Tunnel domain (must match server) |
| `LOCALADDR` | yes | Local TCP address to listen on — connect your app here |

---

## Wire-protocol flags

The three `-client-id-len`, `-icmp-id`, and `-max-label-len` flags must be **identical on both sides**. Mismatches cause silent failures:

| Flag | Mismatch effect |
|------|----------------|
| `-client-id-len` | Server reads wrong prefix length from DNS; ICMP filter fails on client |
| `-icmp-id` | Client ignores all downstream ICMP (ID mismatch) |
| `-max-label-len` | Client truncates queries at a different boundary than server decodes |
| `-record-type` | Server returns NXDOMAIN for every query; tunnel never establishes |

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

## Building from source

```bash
git clone --recurse-submodules <repo>
cd randomshitgobrr/randomshitgobrr
go build -o bin/hybrid-server ./cmd/server
go build -o bin/hybrid-client ./cmd/client
```

If you cloned without `--recurse-submodules`:

```bash
git submodule update --init
```

---

## How it works

```
Client                                  Server
──────────────────────────────────────────────────────────────
App → TCP
      └→ SMUX stream
           └→ Noise NK (encrypted)
                └→ KCP (reliable, MTU=36)
                     └→ DNS TXT query        ──────────────→  UDP :53
                        [clientID:2][len:1][data]                   ↓
                        one 63-char base32 label            Decode VayDNS format
                        per KCP segment                     Feed KCP segment
                                                                    ↓
                                                            KCP → Noise → SMUX → TCP → Upstream

                     ←── ICMP Echo Request (optional spoofed src)  ←─ Raw socket
                         [clientID:2][len:2][KCP]...
                         multiple KCP segments bundled per datagram
```

**Upstream (DNS):** Each KCP segment is encoded as `[clientID:2][datalen:1][data]` and base32-encoded into a single DNS label (≤63 chars). Limiting to one label ensures the query reaches the authoritative nameserver through resolvers that strip multi-label prefixes.

**Downstream (ICMP):** The server sends KCP segments back as ICMP Echo Requests addressed to `-dest-ip`. The ICMP payload starts with the 2-byte client ID so the client can filter its own session. Multiple KCP segments are bundled into one datagram (up to 1400 bytes).

**KCP MTU = 36:** With 24-byte KCP header + 12 bytes of application data per segment, large messages (e.g. the Noise handshake) are fragmented into several segments, each fitting in one DNS label. KCP reassembles them on the other side.

---

## License

MIT — see [LICENSE](LICENSE).

Third-party components retain their original licenses (see `../vaydns` and `../spoof-tunnel`).
