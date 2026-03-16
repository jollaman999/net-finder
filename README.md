# Net Finder

[한국어 문서](docs/README.ko.md)

A real-time network scanner and monitoring dashboard with a built-in web UI. Net Finder discovers hosts on your local network using both IPv4 and IPv6, detects network infrastructure, and monitors for security threats — all from a single static binary.

## Features

- **IPv4 & IPv6 dual-stack support** — Scan IPv4-only, IPv6-only, or both simultaneously with the `-mode` flag
- **ARP-based host discovery** — Scans subnets using ARP requests and passively captures ARP traffic to discover all active IPv4 hosts
- **NDP-based host discovery** — Discovers IPv6 hosts via Neighbor Discovery Protocol multicast solicitations
- **IP conflict detection** — Identifies multiple MAC addresses claiming the same IP (both IPv4 and IPv6), distinguishing real conflicts from NIC bonding/teaming
- **DHCP/DHCPv6 server detection** — Discovers DHCP and DHCPv6 servers on the network and reports offered IPs, subnet masks, routers, and DNS servers
- **Hostname resolution** — Resolves hostnames via DNS PTR, NetBIOS, mDNS, SNMP sysName, TLS certificates, SMTP banners, and LLDP/CDP cross-reference. In IPv6-only mode, uses internal ARP to share hostnames via MAC address matching
- **HTTP/HTTPS service detection** — After the initial scan, runs a background full 65535-port TCP scan on every host. Open ports are probed for HTTP/HTTPS services with automatic identification via HTML titles, `X-*-Version` headers, `Server` headers, and JSON API responses. Follows redirects up to 3 hops. Results are displayed incrementally with real-time progress tracking
- **OUI vendor lookup** — Maps MAC addresses to hardware vendors using the IEEE OUI database
- **Network protocol listeners**
  - **HSRP** (Hot Standby Router Protocol) — Detects Cisco HSRP v1/v2 advertisements
  - **VRRP** (Virtual Router Redundancy Protocol) — Captures VRRP advertisements
  - **LLDP** (Link Layer Discovery Protocol) — Discovers neighboring switches and network devices
  - **CDP** (Cisco Discovery Protocol) — Discovers Cisco devices and their details
- **Security monitoring**
  - **ARP spoofing detection** — Continuously monitors ARP traffic against a baseline, with critical alerts for gateway spoofing
  - **NDP spoofing detection** — Monitors IPv6 NDP traffic for suspicious neighbor advertisements
  - **DNS spoofing detection** — Compares responses from multiple DNS servers to detect mismatches and suspiciously fast responses
- **Email alerts** — Configurable per-subnet email alerts with separate IPv4/IPv6 event selection, encrypted config storage (AES-256-GCM)
- **Web dashboard** — Single-page web UI with real-time scan progress, host lists, conflict alerts, protocol information, and multi-language support (English, Korean, Japanese, Chinese)

## Requirements

- Linux
- Go 1.21+
- Root privileges (required for raw packet capture)

No external C libraries are needed. Net Finder uses Linux AF_PACKET raw sockets directly, producing a fully static binary with no runtime dependencies.

## Build

```bash
make build
```

`CGO_ENABLED=0` is set by default in the Makefile, producing a fully static binary.

Other targets:

```bash
make clean       # Remove the binary
make deps        # Download and tidy Go modules
make fmt         # Format source code
make vet         # Run go vet
```

## Install

```bash
make install    # Install to /usr/local/bin
make uninstall  # Remove from /usr/local/bin
```

## Docker

```bash
make docker-build   # Build Docker image (alpine-based)
make docker-push    # Build and push to Docker Hub
make docker-run     # Run container (--network host, NET_RAW/NET_ADMIN)
make docker-up      # Start with docker compose (detached)
make docker-down    # Stop docker compose
```

Or run directly with Docker:

```bash
docker build -t net-finder .
docker run --rm --network host --cap-add NET_RAW --cap-add NET_ADMIN net-finder
```

`--network host` is required for raw packet capture on the host network. Pass flags after the image name:

```bash
docker run --rm --network host --cap-add NET_RAW --cap-add NET_ADMIN net-finder -i eth0 -p 8080
```

## Usage

```bash
sudo ./net-finder [options]
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `-i` | (auto-detect) | Network interface to use |
| `-s` | (auto-discover) | Subnets to scan (comma-separated CIDR, e.g. `192.168.1.0/24,10.0.0.0/24`) |
| `-p` | `9090` | Web dashboard port |
| `-auto` | `true` | Start scanning automatically on launch |
| `-mode` | `both` | IP version mode: `ipv4`, `ipv6`, or `both` |

### Examples

```bash
# Auto-detect interface and subnet, open dashboard on port 9090
sudo ./net-finder

# Specify interface and subnet
sudo ./net-finder -i eth0 -s 192.168.1.0/24

# Scan multiple subnets on a custom port
sudo ./net-finder -s 192.168.1.0/24,10.0.0.0/24 -p 8080

# IPv6-only scan
sudo ./net-finder -mode ipv6

# IPv4-only scan
sudo ./net-finder -mode ipv4

# Start without auto-scan (manual trigger from the web UI)
sudo ./net-finder -auto=false
```

The web dashboard opens automatically at `http://localhost:9090` (or your chosen port).

## How It Works

1. **OUI database load** — Downloads and caches the IEEE OUI vendor database
2. **Parallel scanning** — Runs all discovery phases concurrently (based on `-mode`):
   - ARP scan across IPv4 subnets and/or NDP scan across IPv6 subnets, followed by hostname resolution
   - DHCP/DHCPv6 server detection, followed by DNS spoofing checks
   - Protocol listeners for HSRP, VRRP, LLDP, and CDP (30-second capture windows)
3. **Background monitoring** — After the initial scan completes, continuously listens for:
   - New HSRP/VRRP/LLDP/CDP advertisements
   - ARP traffic anomalies indicating potential spoofing (IPv4)
   - NDP traffic anomalies indicating potential spoofing (IPv6)
4. **Background HTTP/HTTPS scan** — Full TCP port scan (65535 ports) on each host, probing open ports for HTTP/HTTPS services. IPv4 hosts are scanned first, then IPv6. Results update incrementally in the web UI

Packet capture uses Linux `AF_PACKET` raw sockets with kernel-level BPF filters, bypassing the need for libpcap. Packet parsing is handled by `gopacket/layers` (pure Go).

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/status` | GET | Scan status and progress |
| `/api/scan/start` | POST | Start a new scan |
| `/api/scan/stop` | POST | Stop the current scan |
| `/api/hosts` | GET | Discovered hosts |
| `/api/conflicts` | GET | IP address conflicts |
| `/api/dhcp` | GET | Detected DHCP servers |
| `/api/dhcpv6` | GET | Detected DHCPv6 servers |
| `/api/hsrp` | GET | HSRP advertisements |
| `/api/vrrp` | GET | VRRP advertisements |
| `/api/lldp` | GET | LLDP neighbors |
| `/api/cdp` | GET | CDP neighbors |
| `/api/hostnames` | GET | Resolved hostnames |
| `/api/security/arp` | GET | ARP spoofing alerts |
| `/api/security/ndp` | GET | NDP spoofing alerts |
| `/api/security/dns` | GET | DNS spoofing alerts |
| `/api/mode` | GET | Current IP version mode |
| `/api/interfaces` | GET | Available network interfaces |
| `/api/alerts` | GET/POST/DELETE | Manage email alert configurations |
| `/api/alerts/test` | POST | Send a test alert email |

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
