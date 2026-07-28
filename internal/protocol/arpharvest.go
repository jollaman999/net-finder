package protocol

import (
	crand "crypto/rand"
	"encoding/binary"
	"net"
	"sync"
	"time"

	"net-finder/internal/netutil"
)

// subnetIdentity is the synthetic host identity the scanner presents on a single
// L2-reachable secondary subnet (Case A): a stable random MAC plus a free source
// IP inside that subnet. Reusing the same identity across scans makes each subnet
// look like its own steady host to the switch/firewall rather than one host
// straddling many ranges.
type subnetIdentity struct {
	mac   net.HardwareAddr
	srcIP net.IP // nil until a free source IP has been found
}

// SubnetIdentityStore holds the per-subnet synthetic identities in memory for the
// lifetime of the process. Identities are created lazily and never rotated so
// they stay stable across re-scans and background sweeps.
type SubnetIdentityStore struct {
	mu      sync.Mutex
	ids     map[string]*subnetIdentity
	ouiPool [][3]byte // real vendor OUI prefixes for realistic synthetic MACs
}

// NewSubnetIdentityStore creates an empty identity store.
func NewSubnetIdentityStore() *SubnetIdentityStore {
	return &SubnetIdentityStore{ids: make(map[string]*subnetIdentity)}
}

// SetOUIPool supplies the pool of real vendor OUI prefixes used to synthesize
// MACs. When set, each subnet's synthetic MAC carries a genuine vendor prefix so
// it is indistinguishable from a real device; when empty, a locally-administered
// random MAC is used as a fallback.
func (s *SubnetIdentityStore) SetOUIPool(prefixes [][3]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ouiPool = prefixes
}

// MAC returns the stable synthetic MAC for a subnet, creating a fresh
// locally-administered random MAC on first use.
func (s *SubnetIdentityStore) MAC(subnet string) net.HardwareAddr {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getLocked(subnet).mac
}

// SrcIP returns the chosen free source IP for a subnet, or nil if none has been
// assigned yet.
func (s *SubnetIdentityStore) SrcIP(subnet string) net.IP {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getLocked(subnet).srcIP
}

// SetSrcIP records the free source IP discovered for a subnet.
func (s *SubnetIdentityStore) SetSrcIP(subnet string, ip net.IP) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.getLocked(subnet).srcIP = ip
}

// IsSyntheticMAC reports whether macStr belongs to one of our synthetic
// identities, so passive monitors can ignore our own probe traffic.
func (s *SubnetIdentityStore) IsSyntheticMAC(macStr string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range s.ids {
		if id.mac.String() == macStr {
			return true
		}
	}
	return false
}

// IsSyntheticIP reports whether ipStr is one of our synthetic source IPs.
func (s *SubnetIdentityStore) IsSyntheticIP(ipStr string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range s.ids {
		if id.srcIP != nil && id.srcIP.String() == ipStr {
			return true
		}
	}
	return false
}

func (s *SubnetIdentityStore) getLocked(subnet string) *subnetIdentity {
	id, ok := s.ids[subnet]
	if !ok {
		id = &subnetIdentity{mac: randomMAC(s.ouiPool)}
		s.ids[subnet] = id
	}
	return id
}

// randomMAC generates a random unicast MAC. When an OUI pool is supplied it uses
// a genuine vendor prefix (first 3 octets) plus a random 3-octet suffix, so the
// address looks like a real device. With no pool it falls back to a
// locally-administered random MAC.
func randomMAC(ouiPool [][3]byte) net.HardwareAddr {
	b := make([]byte, 6)
	_, _ = crand.Read(b)
	if n := len(ouiPool); n > 0 {
		idx := binary.BigEndian.Uint32(b[:4]) % uint32(n)
		p := ouiPool[idx]
		b[0], b[1], b[2] = p[0], p[1], p[2] // real vendor OUI; already global unicast
		return net.HardwareAddr(b)
	}
	b[0] = (b[0] & 0xfc) | 0x02 // fallback: locally-administered unicast
	return net.HardwareAddr(b)
}

// HarvestRemoteMACs discovers real MACs for hosts in L2-reachable "remote"
// subnets — secondary IP ranges that live on the same broadcast domain as us but
// outside our own subnet (Case A). For each such subnet it presents a synthetic
// identity (random MAC + free in-subnet source IP) and ARP-scans the range from
// it, so each subnet appears as its own distinct host instead of one host
// touching many ranges.
//
// This only works on flat L2 networks. On networks with Dynamic ARP Inspection
// or port security the spoofed ARP is dropped and logged, so callers gate it
// behind an explicit opt-in. Truly routed subnets simply yield no replies and
// are left to the routed L3 probe path.
func HarvestRemoteMACs(iface *net.Interface, subnets []*net.IPNet, localIP net.IP, store *SubnetIdentityStore, timeout time.Duration) *ARPResult {
	var remote []*net.IPNet
	for _, sn := range subnets {
		if localIP == nil || !sn.Contains(localIP) {
			remote = append(remote, sn)
		}
	}
	if len(remote) == 0 || store == nil {
		return nil
	}

	sock, err := netutil.NewRawSocket(iface.Name)
	if err != nil {
		return nil
	}
	defer sock.Close()
	if err := sock.SetBPFFilter(netutil.BPFFilterARP()); err != nil {
		return nil
	}

	result := NewARPResult()
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		readARPResponses(sock, result, done)
	}()
	time.Sleep(100 * time.Millisecond)

	synthMACs := make(map[string]bool)

	for _, sn := range remote {
		key := sn.String()
		mac := store.MAC(key)
		synthMACs[mac.String()] = true

		srcIP := store.SrcIP(key)
		if srcIP == nil {
			srcIP = pickFreeIP(sock, iface, mac, sn, result, timeout)
			if srcIP == nil {
				// No free source IP found — skip harvesting this subnet rather
				// than risk claiming an in-use address.
				continue
			}
			store.SetSrcIP(key, srcIP)
		}

		targets := netutil.ExpandCIDR(sn)

		send := func(ips []net.IP) {
			for _, t := range ips {
				if t.Equal(srcIP) {
					continue
				}
				netutil.ARPAcquire()
				sendARPRequest(sock, iface, srcIP, mac, t)
			}
		}

		send(targets)
		time.Sleep(timeout)

		// One retry for hosts that didn't answer the first sweep.
		var missing []net.IP
		result.Mu.Lock()
		for _, t := range targets {
			if t.Equal(srcIP) {
				continue
			}
			if _, ok := result.Entries[t.String()]; !ok {
				missing = append(missing, t)
			}
		}
		result.Mu.Unlock()
		if len(missing) > 0 {
			send(missing)
			time.Sleep(timeout)
		}
	}

	close(done)
	wg.Wait()

	// Strip our own synthetic identities: our ARP requests are observed on the
	// wire and self-recorded as {srcIP -> synthetic MAC}.
	result.Mu.Lock()
	for ip, macs := range result.Entries {
		var kept []net.HardwareAddr
		for _, m := range macs {
			if !synthMACs[m.String()] {
				kept = append(kept, m)
			}
		}
		if len(kept) == 0 {
			delete(result.Entries, ip)
		} else {
			result.Entries[ip] = kept
		}
	}
	for _, sn := range remote {
		if src := store.SrcIP(sn.String()); src != nil {
			delete(result.Entries, src.String())
		}
	}
	result.Mu.Unlock()

	return result
}

// pickFreeIP probes a handful of high host addresses in a subnet with RFC 5227
// ARP probes (sender IP 0.0.0.0) and returns the first that draws no reply,
// meaning it is safe to adopt as our synthetic source IP. Common gateway
// suffixes (.1/.254) are skipped. Returns nil if every candidate is in use.
func pickFreeIP(sock *netutil.RawSocket, iface *net.Interface, mac net.HardwareAddr, subnet *net.IPNet, result *ARPResult, timeout time.Duration) net.IP {
	hosts := netutil.ExpandCIDR(subnet)
	if len(hosts) == 0 {
		return nil
	}

	var cands []net.IP
	for i := len(hosts) - 1; i >= 0 && len(cands) < 8; i-- {
		if last := hosts[i].To4()[3]; last == 1 || last == 254 {
			continue // skip common gateway addresses
		}
		cands = append(cands, hosts[i])
	}

	for _, c := range cands {
		netutil.ARPAcquire()
		sendARPRequest(sock, iface, net.IPv4zero, mac, c) // sender 0.0.0.0 = ARP probe
	}
	time.Sleep(timeout)

	result.Mu.Lock()
	defer result.Mu.Unlock()
	for _, c := range cands {
		if _, taken := result.Entries[c.String()]; !taken {
			return c
		}
	}
	return nil
}
