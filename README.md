# Net Finder

[한국어 문서](docs/README.ko.md)

A real-time network scanner and monitoring dashboard with a built-in web UI. Net Finder discovers hosts on your local network, detects network infrastructure, and monitors for security threats — all from a single static binary.

## Features

- **ARP-based host discovery** — Scans subnets using ARP requests and passively captures ARP traffic to discover all active hosts
- **IP conflict detection** — Identifies multiple MAC addresses claiming the same IP, distinguishing real conflicts from NIC bonding/teaming
- **DHCP server detection** — Discovers DHCP servers on the network and reports offered IPs, subnet masks, routers, and DNS servers
- **Hostname resolution** — Resolves hostnames via DNS PTR, NetBIOS, mDNS, SNMP sysName, TLS certificates, and SMTP banners
- **OUI vendor lookup** — Maps MAC addresses to hardware vendors using the IEEE OUI database
- **Network protocol listeners**
  - **HSRP** (Hot Standby Router Protocol) — Detects Cisco HSRP v1/v2 advertisements
  - **VRRP** (Virtual Router Redundancy Protocol) — Captures VRRP advertisements
  - **LLDP** (Link Layer Discovery Protocol) — Discovers neighboring switches and network devices
  - **CDP** (Cisco Discovery Protocol) — Discovers Cisco devices and their details
- **Security monitoring**
  - **ARP spoofing detection** — Continuously monitors ARP traffic against a baseline, with critical alerts for gateway spoofing
  - **DNS spoofing detection** — Compares responses from multiple DNS servers to detect mismatches and suspiciously fast responses
- **Web dashboard** — Single-page web UI with real-time scan progress, host lists, conflict alerts, and protocol information

## Requirements

- Linux
- Go 1.21+
- Root privileges (required for raw packet capture)

No external C libraries are needed. Net Finder uses Linux AF_PACKET raw sockets directly, producing a fully static binary with no runtime dependencies.

## Build

```bash
make build
```

For an explicitly static build with CGo disabled:

```bash
CGO_ENABLED=0 make build
```

Other targets:

```bash
make clean       # Remove the binary
make deps        # Download and tidy Go modules
make fmt         # Format source code
make vet         # Run go vet
```

## Install

```bash
sudo make install    # Install to /usr/local/bin
sudo make uninstall  # Remove from /usr/local/bin
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

### Examples

```bash
# Auto-detect interface and subnet, open dashboard on port 9090
sudo ./net-finder

# Specify interface and subnet
sudo ./net-finder -i eth0 -s 192.168.1.0/24

# Scan multiple subnets on a custom port
sudo ./net-finder -s 192.168.1.0/24,10.0.0.0/24 -p 8080

# Start without auto-scan (manual trigger from the web UI)
sudo ./net-finder -auto=false
```

The web dashboard opens automatically at `http://localhost:9090` (or your chosen port).

## How It Works

1. **OUI database load** — Downloads and caches the IEEE OUI vendor database
2. **Parallel scanning** — Runs all discovery phases concurrently:
   - ARP scan across all target subnets, followed by hostname resolution
   - DHCP server detection, followed by DNS spoofing checks
   - Protocol listeners for HSRP, VRRP, LLDP, and CDP (30-second capture windows)
3. **Background monitoring** — After the initial scan completes, continuously listens for:
   - New HSRP/VRRP/LLDP/CDP advertisements
   - ARP traffic anomalies indicating potential spoofing

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
| `/api/hsrp` | GET | HSRP advertisements |
| `/api/vrrp` | GET | VRRP advertisements |
| `/api/lldp` | GET | LLDP neighbors |
| `/api/cdp` | GET | CDP neighbors |
| `/api/hostnames` | GET | Resolved hostnames |
| `/api/security/arp` | GET | ARP spoofing alerts |
| `/api/security/dns` | GET | DNS spoofing alerts |
| `/api/interfaces` | GET | Available network interfaces |

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
