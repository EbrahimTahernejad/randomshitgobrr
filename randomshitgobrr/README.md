# randomshitgobrr

A hybrid DNS+ICMP tunnel using KCP for reliable transport.

**Upstream (client → server):** DNS TXT queries — works bidirectionally through DNS-based censorship circumvention.
**Downstream (server → client):** ICMP Echo Requests with spoofed source IP — faster than DNS, exploits the fact that outside→inside ICMP is often unrestricted.

Stack: KCP → Noise NK (encryption) → SMUX (multiplexing) → TCP

---

## Credits

This project is built on top of two existing tools:

- **[dnstt](https://www.bamsoftware.com/git/dnstt.git)** by David Fifield — DNS tunnel using KCP, Noise, and SMUX. The DNS encoding, turbotunnel queue design, and overall protocol structure come directly from dnstt. Licensed under the MIT License.

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
  -spoof-src <SPOOF_IP> \
  t.example.com \
  127.0.0.1:8000
```

| Flag | Required | Description |
|------|----------|-------------|
| `-udp :53` | yes | UDP address to listen for DNS queries |
| `-dest-ip` | yes | Client's public IPv4 — where to send downstream ICMP |
| `-privkey-file` | recommended | Private key file (omit to generate a temporary key) |
| `-spoof-src` | no | Source IP to spoof in downstream ICMP packets (e.g. `1.1.1.1`). Omit for normal ICMP. |
| `t.example.com` | yes | Tunnel domain (must match NS delegation) |
| `127.0.0.1:8000` | yes | Upstream TCP address to forward tunneled connections to |

**Suppress kernel ICMP auto-replies** so the OS doesn't respond to your spoofed ICMP on behalf of the spoof-src IP:

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
| `t.example.com` | yes | Tunnel domain (must match server) |
| `127.0.0.1:7000` | yes | Local TCP address to listen on — connect your app here |

---

## Using the tunnel

Once the client is running, connect your application to the local address:

```bash
# SSH through the tunnel (if upstream is an SSH server)
ssh user@127.0.0.1 -p 7000

# SOCKS proxy (if upstream is a SOCKS server)
curl --socks5 127.0.0.1:7000 https://example.com
```

The client accepts TCP connections on `127.0.0.1:7000` and forwards them through the tunnel to the server's upstream address.

---

## Building from source

```bash
git clone --recurse-submodules <repo>
cd randomshitgobrr
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
Client (inside Iran)                    Server (outside)
─────────────────────────────────────────────────────────
App → TCP
      └→ SMUX stream
           └→ Noise NK (encrypted)
                └→ KCP (reliable)
                     └→ DNS TXT query  ──────────────→  UDP :53
                                                              ↓
                                                        Decode query
                                                        Feed into KCP
                                                              ↓
                                                        KCP → Noise → SMUX → TCP → Upstream

                     ←── ICMP Echo Request (spoofed src)  ←─ Raw socket
                    (ClientID + bundled KCP packets in payload)
```

- The client embeds a random 8-byte **ClientID** in every DNS query so the server can identify the session.
- The server sends all downstream data as **ICMP Echo Requests** to the configured `-dest-ip`, with the ClientID as a prefix in the ICMP payload so the client can filter its own packets.
- Each ICMP datagram bundles as many KCP packets as fit within 1400 bytes.
- KCP MTU is derived from the DNS name capacity of the tunnel domain, ensuring upstream packets always fit in a single DNS query name.

---

## License

MIT — see [LICENSE](LICENSE).

Third-party components retain their original licenses (see `../dnstt` and `../spoof-tunnel`).
