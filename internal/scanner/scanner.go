package scanner

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"net-finder/internal/alert"
	"net-finder/internal/hostname"
	"net-finder/internal/models"
	"net-finder/internal/netutil"
	"net-finder/internal/oui"
	"net-finder/internal/protocol"
)

// Scanner orchestrates all scanning operations
type Scanner struct {
	iface     *net.Interface
	localIP   net.IP
	localMAC  net.HardwareAddr
	subnets   []*net.IPNet
	subnetsMu sync.RWMutex // guards subnets (dynamically extended at runtime)
	oui       *oui.OUIDatabase
	alertMgr  *alert.AlertManager

	// IPv6 fields
	localIPv6     net.IP
	linkLocalIPv6 net.IP
	subnetsV6     []*net.IPNet
	subnetsV6Mu   sync.RWMutex // guards subnetsV6 (dynamically extended at runtime)
	ipMode        models.IPMode
	ndpResult     *protocol.NDPResult

	state models.ScanState

	stopCh   chan struct{}
	bgStopCh chan struct{}
	running  bool
	runMu    sync.Mutex

	arpResult      *protocol.ARPResult
	hostnameMap    map[string]string
	hostnameMu     sync.RWMutex
	emailedARPKeys map[string]bool
	emailedNDPKeys map[string]bool

	// Background note scanning progress
	noteScanTotal   int
	noteScanDone    int
	noteScanRunning bool
	noteScanMu      sync.RWMutex

	// Count of in-flight background scan tasks (passive-discovery sweeps and
	// periodic host/conflict reverification) surfaced in the UI status.
	bgScanActive int
	bgScanMu     sync.Mutex

	// Per-host miss count for liveness tracking (IPv4)
	hostMissCount map[string]int
	hostMissMu    sync.Mutex

	// L2 MAC harvesting for same-broadcast-domain secondary subnets (Case A):
	// remote (non-attached) subnets are ARP-scanned from a stable per-subnet
	// synthetic identity to recover real MACs.
	subnetIDs *protocol.SubnetIdentityStore
}

// bgScanBegin/bgScanEnd bracket a background scan task; bgScanning reports
// whether any such task is currently running.
func (s *Scanner) bgScanBegin() {
	s.bgScanMu.Lock()
	s.bgScanActive++
	s.bgScanMu.Unlock()
}

func (s *Scanner) bgScanEnd() {
	s.bgScanMu.Lock()
	if s.bgScanActive > 0 {
		s.bgScanActive--
	}
	s.bgScanMu.Unlock()
}

func (s *Scanner) bgScanning() bool {
	s.bgScanMu.Lock()
	defer s.bgScanMu.Unlock()
	return s.bgScanActive > 0
}

// NewScanner creates a new Scanner instance
func NewScanner(iface *net.Interface, localIP, localIPv6, linkLocalIPv6 net.IP,
	localMAC net.HardwareAddr, subnets, subnetsV6 []*net.IPNet,
	ipMode models.IPMode, alertMgr *alert.AlertManager) *Scanner {
	return &Scanner{
		iface:         iface,
		localIP:       localIP,
		localMAC:      localMAC,
		subnets:       subnets,
		localIPv6:     localIPv6,
		linkLocalIPv6: linkLocalIPv6,
		subnetsV6:     subnetsV6,
		ipMode:        ipMode,
		alertMgr:      alertMgr,
		state: models.ScanState{
			Status: "idle",
			IPMode: ipMode,
		},
		hostnameMap:    make(map[string]string),
		emailedARPKeys: make(map[string]bool),
		emailedNDPKeys: make(map[string]bool),
		hostMissCount:  make(map[string]int),
		subnetIDs:      protocol.NewSubnetIdentityStore(),
	}
}

// Start begins the scan pipeline
func (s *Scanner) Start() {
	s.runMu.Lock()
	if s.running {
		s.runMu.Unlock()
		return
	}
	s.running = true
	s.stopCh = make(chan struct{})
	s.bgStopCh = make(chan struct{})
	s.runMu.Unlock()

	go s.run()
}

// Stop halts the scan and background listeners
func (s *Scanner) Stop() {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	if !s.running {
		return
	}
	close(s.stopCh)
	// Also stop background listeners
	select {
	case <-s.bgStopCh:
	default:
		close(s.bgStopCh)
	}
	s.running = false
	s.state.Mu.Lock()
	s.state.Status = "idle"
	s.state.Progress = models.ProgressInfo{}
	s.state.Mu.Unlock()
}

// IsRunning returns whether a scan is active
func (s *Scanner) IsRunning() bool {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	return s.running
}

func (s *Scanner) stopped() bool {
	select {
	case <-s.stopCh:
		return true
	default:
		return false
	}
}

func (s *Scanner) setProgress(phase string, percent, count int) {
	s.state.Mu.Lock()
	s.state.Progress = models.ProgressInfo{
		Phase:   phase,
		Percent: percent,
		Count:   count,
	}
	s.state.Mu.Unlock()
}

// GetStatus returns current scan status and progress
func (s *Scanner) GetStatus() map[string]interface{} {
	var subnetStrs []string
	for _, sn := range s.snapshotSubnets() {
		subnetStrs = append(subnetStrs, sn.String())
	}
	for _, sn := range s.snapshotSubnetsV6() {
		subnetStrs = append(subnetStrs, sn.String())
	}
	netutil.SortCIDRStrings(subnetStrs)

	bgScanning := s.bgScanning()

	s.state.Mu.RLock()
	defer s.state.Mu.RUnlock()
	s.noteScanMu.RLock()
	noteProgress := map[string]interface{}{
		"running": s.noteScanRunning,
		"total":   s.noteScanTotal,
		"done":    s.noteScanDone,
	}
	s.noteScanMu.RUnlock()

	return map[string]interface{}{
		"status":     s.state.Status,
		"progress":   s.state.Progress,
		"subnets":    subnetStrs,
		"ipMode":     s.ipMode,
		"noteScan":   noteProgress,
		"bgScanning": bgScanning,
	}
}

// GetHosts returns the host list
func (s *Scanner) GetHosts() []models.HostEntry {
	s.state.Mu.RLock()
	defer s.state.Mu.RUnlock()
	if s.state.Hosts == nil {
		return []models.HostEntry{}
	}
	return s.state.Hosts
}

// GetConflicts returns conflict entries
func (s *Scanner) GetConflicts() []models.ConflictEntry {
	s.state.Mu.RLock()
	defer s.state.Mu.RUnlock()
	if s.state.Conflicts == nil {
		return []models.ConflictEntry{}
	}
	return s.state.Conflicts
}

// GetDHCPServers returns detected DHCP servers
func (s *Scanner) GetDHCPServers() []models.DHCPServerJSON {
	s.state.Mu.RLock()
	defer s.state.Mu.RUnlock()
	if s.state.DHCPServers == nil {
		return []models.DHCPServerJSON{}
	}
	return s.state.DHCPServers
}

// GetHSRP returns HSRP entries
func (s *Scanner) GetHSRP() []models.HSRPEntry {
	s.state.Mu.RLock()
	defer s.state.Mu.RUnlock()
	if s.state.HSRPEntries == nil {
		return []models.HSRPEntry{}
	}
	return s.state.HSRPEntries
}

// GetVRRP returns VRRP entries
func (s *Scanner) GetVRRP() []models.VRRPEntry {
	s.state.Mu.RLock()
	defer s.state.Mu.RUnlock()
	if s.state.VRRPEntries == nil {
		return []models.VRRPEntry{}
	}
	return s.state.VRRPEntries
}

// GetLLDP returns LLDP neighbors
func (s *Scanner) GetLLDP() []models.LLDPNeighbor {
	s.state.Mu.RLock()
	defer s.state.Mu.RUnlock()
	if s.state.LLDPNeighbors == nil {
		return []models.LLDPNeighbor{}
	}
	return s.state.LLDPNeighbors
}

// GetCDP returns CDP neighbors
func (s *Scanner) GetCDP() []models.CDPNeighbor {
	s.state.Mu.RLock()
	defer s.state.Mu.RUnlock()
	if s.state.CDPNeighbors == nil {
		return []models.CDPNeighbor{}
	}
	return s.state.CDPNeighbors
}

// GetHostnames returns hostname entries
func (s *Scanner) GetHostnames() []models.HostnameEntry {
	s.state.Mu.RLock()
	defer s.state.Mu.RUnlock()
	if s.state.Hostnames == nil {
		return []models.HostnameEntry{}
	}
	return s.state.Hostnames
}

// GetARPAlerts returns ARP spoof alerts
func (s *Scanner) GetARPAlerts() []models.ARPSpoofAlert {
	s.state.Mu.RLock()
	defer s.state.Mu.RUnlock()
	if s.state.ARPAlerts == nil {
		return []models.ARPSpoofAlert{}
	}
	return s.state.ARPAlerts
}

// GetDNSAlerts returns DNS spoof alerts
func (s *Scanner) GetDNSAlerts() []models.DNSSpoofAlert {
	s.state.Mu.RLock()
	defer s.state.Mu.RUnlock()
	if s.state.DNSAlerts == nil {
		return []models.DNSSpoofAlert{}
	}
	return s.state.DNSAlerts
}

// GetNDPAlerts returns NDP spoof alerts
func (s *Scanner) GetNDPAlerts() []models.NDPSpoofAlert {
	s.state.Mu.RLock()
	defer s.state.Mu.RUnlock()
	if s.state.NDPAlerts == nil {
		return []models.NDPSpoofAlert{}
	}
	return s.state.NDPAlerts
}

// GetDHCPv6Servers returns detected DHCPv6 servers
func (s *Scanner) GetDHCPv6Servers() []models.DHCPv6ServerJSON {
	s.state.Mu.RLock()
	defer s.state.Mu.RUnlock()
	if s.state.DHCPv6Servers == nil {
		return []models.DHCPv6ServerJSON{}
	}
	return s.state.DHCPv6Servers
}

// GetIPMode returns current IP mode
func (s *Scanner) GetIPMode() models.IPMode {
	return s.ipMode
}

// SetIPMode updates the IP mode
func (s *Scanner) SetIPMode(mode models.IPMode) {
	s.ipMode = mode
	s.state.Mu.Lock()
	s.state.IPMode = mode
	s.state.Mu.Unlock()
}

// GetInterfaces returns available network interfaces
func GetInterfaces(currentIface string) []models.InterfaceInfo {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	var result []models.InterfaceInfo
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if len(iface.HardwareAddr) == 0 {
			continue
		}

		info := models.InterfaceInfo{
			Name:    iface.Name,
			MAC:     iface.HardwareAddr.String(),
			Up:      iface.Flags&net.FlagUp != 0,
			Current: iface.Name == currentIface,
		}

		addrs, err := iface.Addrs()
		if err == nil {
			for _, addr := range addrs {
				if ipnet, ok := addr.(*net.IPNet); ok {
					info.IPs = append(info.IPs, ipnet.IP.String())
				}
			}
		}

		result = append(result, info)
	}
	return result
}

// run executes the full scan pipeline
func (s *Scanner) run() {
	defer func() {
		s.runMu.Lock()
		s.running = false
		s.runMu.Unlock()
	}()

	s.emailedARPKeys = make(map[string]bool)
	s.emailedNDPKeys = make(map[string]bool)

	s.state.Mu.Lock()
	s.state.Status = "running"
	s.state.Hosts = nil
	s.state.Conflicts = nil
	s.state.DHCPServers = nil
	s.state.DHCPv6Servers = nil
	s.state.HSRPEntries = nil
	s.state.VRRPEntries = nil
	s.state.LLDPNeighbors = nil
	s.state.CDPNeighbors = nil
	s.state.Hostnames = nil
	s.state.ARPAlerts = nil
	s.state.DNSAlerts = nil
	s.state.NDPAlerts = nil
	s.state.IPMode = s.ipMode
	s.state.Mu.Unlock()

	// Phase 1: Load OUI (0-5%)
	s.setProgress("oui_loading", 0, 0)
	if s.stopped() {
		return
	}

	ouiDB, err := oui.LoadOUI()
	if err != nil {
		log.Printf("failed to load OUI: %v", err)
		ouiDB = &oui.OUIDatabase{
			Vendors: make(map[string]string),
		}
	}
	s.oui = ouiDB
	// Seed synthetic-identity MACs with real vendor OUIs so cross-subnet probes
	// look like genuine devices rather than software-generated addresses.
	if s.subnetIDs != nil {
		s.subnetIDs.SetOUIPool(ouiDB.OUIPrefixes())
	}
	s.setProgress("oui_done", 5, len(ouiDB.Vendors))
	if s.stopped() {
		return
	}

	// All phases run in parallel after OUI load
	s.setProgress("scan_parallel", 10, 0)

	var scanWg sync.WaitGroup

	// ── ARP Scan (IPv4, parallel branch 1) ──
	if s.ipMode != models.IPModeIPv6 && s.localIP != nil {
		scanWg.Add(1)
		go func() {
			defer scanWg.Done()
			subs := s.snapshotSubnets()
			result, err := protocol.ARPScan(s.iface, s.localIP, s.localMAC, subs, 3*time.Second)
			if err != nil {
				log.Printf("ARP scan failed: %v", err)
			} else {
				s.arpResult = result
				s.processARPResults(result)
			}
			// Remote (routed) subnets: discover via L3 probes, never ARP spoofing.
			s.probeRemoteSubnets(subs)
			s.setProgress("scan_arp_done", 30, len(s.GetHosts()))
		}()
	}

	// ── NDP Scan (IPv6, parallel branch 1b) ──
	if s.ipMode != models.IPModeIPv4 && (s.localIPv6 != nil || s.linkLocalIPv6 != nil) {
		scanWg.Add(1)
		go func() {
			defer scanWg.Done()
			srcIPv6 := s.localIPv6
			if srcIPv6 == nil {
				srcIPv6 = s.linkLocalIPv6
			}
			log.Printf("NDP scan starting (source: %s)", srcIPv6)
			result, err := protocol.NDPScan(s.iface, srcIPv6, s.localMAC, s.snapshotSubnetsV6(), 3*time.Second)
			if err != nil {
				log.Printf("NDP scan failed: %v", err)
				return
			}
			log.Printf("NDP scan complete: %d hosts found", len(result.Entries))
			s.ndpResult = result
			s.processNDPResults(result)
			s.setProgress("scan_ndp_done", 35, len(s.GetHosts()))
		}()
	}

	// ── DHCP Detection → DNS Spoofing Check (IPv4, parallel branch 2) ──
	if s.ipMode != models.IPModeIPv6 {
		scanWg.Add(1)
		go func() {
			defer scanWg.Done()
			servers, err := protocol.DetectDHCP(s.iface, s.localMAC, 5*time.Second)
			if err != nil {
				log.Printf("DHCP detection failed: %v", err)
				return
			}
			s.processDHCPResults(servers)

			if s.stopped() {
				return
			}
			// DNS spoofing check immediately after DHCP
			s.checkDNSSpoofing()
		}()
	}

	// ── DHCPv6 Detection (IPv6, parallel branch 2b) ──
	if s.ipMode != models.IPModeIPv4 && (s.localIPv6 != nil || s.linkLocalIPv6 != nil) {
		scanWg.Add(1)
		go func() {
			defer scanWg.Done()
			srcIPv6 := s.linkLocalIPv6
			if srcIPv6 == nil {
				srcIPv6 = s.localIPv6
			}
			servers, err := protocol.DetectDHCPv6(s.iface, s.localMAC, srcIPv6, 5*time.Second)
			if err != nil {
				log.Printf("DHCPv6 detection failed: %v", err)
				return
			}
			s.processDHCPv6Results(servers)
		}()
	}

	// ── Protocol Listeners: HSRP/VRRP/LLDP/CDP (parallel branch 3) ──
	scanWg.Add(4)
	go func() {
		defer scanWg.Done()
		entries, err := protocol.ListenHSRP(s.iface.Name, 30*time.Second, s.stopCh, s.ipMode)
		if err != nil {
			log.Printf("HSRP listener error: %v", err)
			return
		}
		s.state.Mu.Lock()
		s.state.HSRPEntries = append(s.state.HSRPEntries, entries...)
		s.state.Mu.Unlock()
	}()
	go func() {
		defer scanWg.Done()
		entries, err := protocol.ListenVRRP(s.iface.Name, 30*time.Second, s.stopCh, s.ipMode)
		if err != nil {
			log.Printf("VRRP listener error: %v", err)
			return
		}
		s.state.Mu.Lock()
		s.state.VRRPEntries = append(s.state.VRRPEntries, entries...)
		s.state.Mu.Unlock()
	}()
	go func() {
		defer scanWg.Done()
		entries, err := protocol.ListenLLDP(s.iface.Name, 30*time.Second, s.stopCh)
		if err != nil {
			log.Printf("LLDP listener error: %v", err)
			return
		}
		s.state.Mu.Lock()
		s.state.LLDPNeighbors = append(s.state.LLDPNeighbors, entries...)
		s.state.Mu.Unlock()
	}()
	go func() {
		defer scanWg.Done()
		entries, err := protocol.ListenCDP(s.iface.Name, 30*time.Second, s.stopCh)
		if err != nil {
			log.Printf("CDP listener error: %v", err)
			return
		}
		s.state.Mu.Lock()
		s.state.CDPNeighbors = append(s.state.CDPNeighbors, entries...)
		s.state.Mu.Unlock()
	}()

	scanWg.Wait()

	if s.stopped() {
		return
	}

	// Hostname resolution after all host discovery is done
	s.setProgress("hostname_resolving", 90, len(s.GetHosts()))
	s.resolveHostnames()

	if s.stopped() {
		return
	}

	s.setProgress("scan_done", 100, 0)
	s.state.Mu.Lock()
	s.state.Status = "done"
	s.state.Mu.Unlock()

	// Start background listeners
	go s.backgroundProtocolListeners()
	if s.ipMode != models.IPModeIPv6 {
		go s.backgroundARPMonitor()
	}
	if s.ipMode != models.IPModeIPv4 {
		go s.backgroundNDPMonitor()
	}

	// Background note resolution (full port scan → HTTP title)
	go s.backgroundResolveNotes()
}

// processARPResults converts ARPResult into Hosts and Conflicts
// All discovered IPs go into Hosts. Only real conflicts (not bonds) go into Conflicts.
func (s *Scanner) processARPResults(result *protocol.ARPResult) {
	result.Mu.Lock()
	defer result.Mu.Unlock()

	var hosts []models.HostEntry
	var conflicts []models.ConflictEntry

	for ipStr, macs := range result.Entries {
		ip := net.ParseIP(ipStr)
		subnet := s.findSubnet(ip)

		// First MAC for host entry
		mac := macs[0]
		vendor := "Unknown"
		if s.oui != nil {
			vendor = s.oui.Lookup(mac)
		}

		// Every IP goes into the host list
		host := models.HostEntry{
			IP:        ipStr,
			MAC:       mac.String(),
			Vendor:    vendor,
			Subnet:    subnet,
			IPVersion: 4,
		}

		// Multiple MACs → check if bond or real conflict
		if len(macs) > 1 {
			devGroups := netutil.GroupMACsByDevice(macs)
			isBond := len(devGroups) == 1

			var macStrs []string
			var vendorStrs []string
			for _, m := range macs {
				macStrs = append(macStrs, m.String())
				if s.oui != nil {
					vendorStrs = append(vendorStrs, s.oui.Lookup(m))
				}
			}

			if isBond {
				host.IsBond = true
				host.BondMACs = macStrs
				host.BondVendors = vendorStrs
			} else {
				conflicts = append(conflicts, models.ConflictEntry{
					IP:      ipStr,
					MACs:    macStrs,
					Vendors: vendorStrs,
					Subnet:  subnet,
				})
			}
		}

		hosts = append(hosts, host)
	}

	// Sort hosts by IP
	ips := make([]string, len(hosts))
	for i, h := range hosts {
		ips[i] = h.IP
	}
	netutil.SortIPStrings(ips)
	ipIndex := make(map[string]int)
	for i, ip := range ips {
		ipIndex[ip] = i
	}
	sorted := make([]models.HostEntry, len(hosts))
	for _, h := range hosts {
		sorted[ipIndex[h.IP]] = h
	}

	s.state.Mu.Lock()
	// Preserve hosts from other IP versions (e.g. IPv6 from NDP)
	var keep []models.HostEntry
	for _, h := range s.state.Hosts {
		if h.IPVersion != 4 {
			keep = append(keep, h)
		}
	}
	s.state.Hosts = append(keep, sorted...)
	classifyConflicts(conflicts)
	s.state.Conflicts = conflicts
	s.state.Mu.Unlock()

	// Send alerts for discovered hosts
	if s.alertMgr != nil && len(sorted) > 0 {
		go s.alertMgr.SendHostAlerts(sorted)
	}

	// Send alerts only for genuine conflicts, not VIP/bond/SDN patterns.
	realConflicts := filterRealConflicts(conflicts)
	if s.alertMgr != nil && len(realConflicts) > 0 {
		go s.alertMgr.SendConflictAlerts(realConflicts)
	}
}

// filterRealConflicts returns only the entries classified as genuine conflicts.
func filterRealConflicts(conflicts []models.ConflictEntry) []models.ConflictEntry {
	var out []models.ConflictEntry
	for _, c := range conflicts {
		if c.Kind == "conflict" {
			out = append(out, c)
		}
	}
	return out
}

// reclassifyAndAlert re-runs conflict classification over the full conflict set
// (cross-IP signals need the whole set) and alerts only for newly-added entries
// that remain genuine conflicts.
func (s *Scanner) reclassifyAndAlert(addedIPs map[string]bool) {
	s.state.Mu.Lock()
	classifyConflicts(s.state.Conflicts)
	var realAdded []models.ConflictEntry
	for _, c := range s.state.Conflicts {
		if addedIPs[c.IP] && c.Kind == "conflict" {
			realAdded = append(realAdded, c)
		}
	}
	s.state.Mu.Unlock()
	if len(realAdded) > 0 && s.alertMgr != nil {
		go s.alertMgr.SendConflictAlerts(realAdded)
	}
}

// processDHCPResults converts DHCPServerInfo to DHCPServerJSON
func (s *Scanner) processDHCPResults(servers []models.DHCPServerInfo) {
	var result []models.DHCPServerJSON
	for _, srv := range servers {
		entry := models.DHCPServerJSON{
			LeaseTime: srv.LeaseTime,
		}
		if srv.ServerIP != nil {
			entry.ServerIP = srv.ServerIP.String()
		}
		if srv.ServerMAC != nil {
			entry.ServerMAC = srv.ServerMAC.String()
			if s.oui != nil {
				entry.Vendor = s.oui.Lookup(srv.ServerMAC)
			}
		}
		if srv.OfferedIP != nil {
			entry.OfferedIP = srv.OfferedIP.String()
		}
		if srv.SubnetMask != nil {
			entry.SubnetMask = net.IP(srv.SubnetMask).String()
		}
		if srv.Router != nil {
			entry.Router = srv.Router.String()
		}
		for _, dns := range srv.DNS {
			entry.DNS = append(entry.DNS, dns.String())
		}
		result = append(result, entry)
	}

	s.state.Mu.Lock()
	s.state.DHCPServers = result
	s.state.Mu.Unlock()

	// Send alerts for detected DHCP servers
	if s.alertMgr != nil && len(result) > 0 {
		go s.alertMgr.SendDHCPAlerts(result)
	}
}

// resolveHostnames resolves DNS PTR for all discovered hosts.
// Safe to call concurrently from multiple goroutines - only resolves
// IPs not yet in hostnameMap and merges results.
// Also shares hostnames across IPv4/IPv6 hosts with the same MAC.
func (s *Scanner) resolveHostnames() {
	s.state.Mu.RLock()
	hostsCopy := make([]models.HostEntry, len(s.state.Hosts))
	copy(hostsCopy, s.state.Hosts)
	s.state.Mu.RUnlock()

	// In IPv6-only mode, do an internal ARP scan to obtain IPv4→MAC mappings.
	// Hostnames resolved from IPv4 will be shared to IPv6 hosts via MAC matching.
	if s.ipMode == models.IPModeIPv6 {
		if extra := s.arpForHostnames(); len(extra) > 0 {
			hostsCopy = append(hostsCopy, extra...)
		}
	}

	// Only resolve IPs we haven't resolved yet
	var ips []string
	s.hostnameMu.RLock()
	for _, h := range hostsCopy {
		if _, ok := s.hostnameMap[h.IP]; !ok {
			ips = append(ips, h.IP)
		}
	}
	s.hostnameMu.RUnlock()

	if len(ips) > 0 {
		entries := hostname.ResolveHostnames(ips)

		// Merge into hostname map
		s.hostnameMu.Lock()
		for _, e := range entries {
			s.hostnameMap[e.IP] = e.Hostname
		}
		s.hostnameMu.Unlock()
	}

	// Collect hostnames from LLDP SysName / CDP DeviceID by MAC
	s.state.Mu.RLock()
	macProtoName := make(map[string]string)
	for _, e := range s.state.LLDPNeighbors {
		if e.SysName != "" && e.SourceMAC != "" {
			macProtoName[strings.ToLower(e.SourceMAC)] = e.SysName
		}
	}
	for _, e := range s.state.CDPNeighbors {
		if e.DeviceID != "" && e.SourceMAC != "" {
			mac := strings.ToLower(e.SourceMAC)
			if _, exists := macProtoName[mac]; !exists {
				macProtoName[mac] = e.DeviceID
			}
		}
	}
	s.state.Mu.RUnlock()

	// Share hostnames across hosts with same MAC (IPv4 ↔ IPv6)
	// Also fill from LLDP/CDP names
	s.hostnameMu.Lock()
	macHostname := make(map[string]string)
	// First pass: collect known hostnames per MAC
	for _, h := range hostsCopy {
		if hn, ok := s.hostnameMap[h.IP]; ok && hn != "" {
			mac := strings.ToLower(h.MAC)
			if mac != "" {
				macHostname[mac] = hn
			}
		}
	}
	// Merge LLDP/CDP names (don't override existing hostnames)
	for mac, name := range macProtoName {
		if _, exists := macHostname[mac]; !exists {
			macHostname[mac] = name
		}
	}
	// Second pass: fill missing hostnames from MAC match
	for _, h := range hostsCopy {
		if hn, ok := s.hostnameMap[h.IP]; (!ok || hn == "") && h.MAC != "" {
			mac := strings.ToLower(h.MAC)
			if shared, found := macHostname[mac]; found {
				s.hostnameMap[h.IP] = shared
			}
		}
	}
	s.hostnameMu.Unlock()

	// Update all hosts and conflicts with hostnames
	s.state.Mu.Lock()
	s.hostnameMu.RLock()
	for i := range s.state.Hosts {
		if hn, ok := s.hostnameMap[s.state.Hosts[i].IP]; ok {
			s.state.Hosts[i].Hostname = hn
		}
	}
	for i := range s.state.Conflicts {
		if hn, ok := s.hostnameMap[s.state.Conflicts[i].IP]; ok {
			s.state.Conflicts[i].Hostname = hn
		}
	}
	// Rebuild full Hostnames list from map
	s.state.Hostnames = nil
	for ip, hn := range s.hostnameMap {
		s.state.Hostnames = append(s.state.Hostnames, models.HostnameEntry{IP: ip, Hostname: hn})
	}
	s.hostnameMu.RUnlock()
	s.state.Mu.Unlock()
}

// backgroundResolveNotes runs a full port scan + HTTP title probe in background.
// Results are applied incrementally as they are discovered.
func (s *Scanner) backgroundResolveNotes() {
	s.state.Mu.RLock()
	var v4ips, v6ips []string
	for _, h := range s.state.Hosts {
		if h.Note != "" {
			continue
		}
		if h.IPVersion == 4 {
			v4ips = append(v4ips, h.IP)
		} else {
			v6ips = append(v6ips, h.IP)
		}
	}
	s.state.Mu.RUnlock()

	totalIPs := len(v4ips) + len(v6ips)
	if totalIPs == 0 {
		return
	}

	s.noteScanMu.Lock()
	s.noteScanTotal = totalIPs
	s.noteScanDone = 0
	s.noteScanRunning = true
	s.noteScanMu.Unlock()

	setNote := func(ip, note string) {
		s.state.Mu.Lock()
		for i := range s.state.Hosts {
			if s.state.Hosts[i].IP == ip {
				s.state.Hosts[i].Note = note
				break
			}
		}
		s.state.Mu.Unlock()
	}
	incDone := func() {
		s.noteScanMu.Lock()
		s.noteScanDone++
		s.noteScanMu.Unlock()
	}

	bgStopped := func() bool {
		select {
		case <-s.bgStopCh:
			return true
		default:
			return false
		}
	}

	// Phase 1: IPv4 hosts. A fast SYN scan finds open ports across all hosts at
	// once (no per-port connect timeout), then each host's open ports are probed
	// for HTTP/HTTPS/DB services. Falls back to connect scanning when the
	// interface has no IPv4 address.
	if len(v4ips) > 0 && s.localIP != nil {
		ports := allTCPPorts()
		// Scan in batches so notes and progress appear periodically rather than
		// only after the whole host set finishes.
		const batchSize = 128
		for start := 0; start < len(v4ips) && !bgStopped(); start += batchSize {
			end := min(start+batchSize, len(v4ips))
			batch := v4ips[start:end]
			var targets []net.IP
			for _, ipStr := range batch {
				if ip := net.ParseIP(ipStr); ip != nil {
					targets = append(targets, ip)
				}
			}
			openMap := protocol.SYNScanIPv4(s.iface, s.localIP, targets, ports, 3*time.Second, s.bgStopCh)
			for _, ipStr := range batch {
				if bgStopped() {
					break
				}
				if note := hostname.ProbeServices(ipStr, openMap[ipStr], s.bgStopCh); note != "" {
					setNote(ipStr, note)
				}
				incDone()
			}
		}
	} else if len(v4ips) > 0 {
		hostname.ResolveNotesStream(v4ips, s.bgStopCh, setNote, incDone)
	}

	// Phase 2: IPv6 hosts, same two steps as IPv4. Link-local targets are probed
	// from our link-local address and global ones from the global address, so the
	// scan runs whenever the interface has either. Falls back to connect scanning
	// when it has neither.
	if len(v6ips) > 0 && (s.localIPv6 != nil || s.linkLocalIPv6 != nil) {
		ports := allTCPPorts()
		const batchSize = 128
		for start := 0; start < len(v6ips) && !bgStopped(); start += batchSize {
			end := min(start+batchSize, len(v6ips))
			batch := v6ips[start:end]
			var targets []net.IP
			for _, ipStr := range batch {
				if ip := net.ParseIP(ipStr); ip != nil {
					targets = append(targets, ip)
				}
			}
			openMap := protocol.SYNScanIPv6(s.iface, s.localIPv6, s.linkLocalIPv6, targets, ports, 3*time.Second, s.bgStopCh)
			for _, ipStr := range batch {
				if bgStopped() {
					break
				}
				if note := hostname.ProbeServices(ipStr, openMap[ipStr], s.bgStopCh); note != "" {
					setNote(ipStr, note)
				}
				incDone()
			}
		}
	} else if len(v6ips) > 0 {
		hostname.ResolveNotesStream(v6ips, s.bgStopCh, setNote, incDone)
	}

	s.noteScanMu.Lock()
	s.noteScanRunning = false
	s.noteScanMu.Unlock()
}

// allTCPPorts returns the full 1-65535 TCP port list for a SYN scan.
func allTCPPorts() []int {
	ports := make([]int, 65535)
	for i := range ports {
		ports[i] = i + 1
	}
	return ports
}

// arpForHostnames does a quick ARP scan to get IPv4→MAC mappings for hostname resolution.
// Used in IPv6-only mode so that hostnames resolved from IPv4 can be shared to IPv6 hosts via MAC.
func (s *Scanner) arpForHostnames() []models.HostEntry {
	localIP, _, err := netutil.GetInterfaceAddr(s.iface)
	if err != nil || localIP == nil {
		return nil
	}
	subnets := netutil.ParseSubnets("", s.iface)
	if len(subnets) == 0 {
		return nil
	}
	log.Printf("starting internal ARP scan for hostname resolution")
	result, err := protocol.ARPScan(s.iface, localIP, s.localMAC, subnets, 3*time.Second)
	if err != nil {
		log.Printf("ARP scan for hostnames failed: %v", err)
		return nil
	}
	var hosts []models.HostEntry
	for ip, macs := range result.Entries {
		if len(macs) > 0 {
			hosts = append(hosts, models.HostEntry{
				IP:  ip,
				MAC: macs[0].String(),
			})
		}
	}
	log.Printf("ARP scan for hostnames complete: %d IPv4 hosts", len(hosts))
	return hosts
}

// checkDNSSpoofing runs DNS spoofing verification
func (s *Scanner) checkDNSSpoofing() {
	s.state.Mu.RLock()
	var dnsServers []string
	for _, srv := range s.state.DHCPServers {
		for _, dns := range srv.DNS {
			dnsServers = append(dnsServers, dns)
		}
	}
	s.state.Mu.RUnlock()

	if len(dnsServers) == 0 {
		return
	}

	alerts := protocol.CheckDNSSpoofing(dnsServers)
	if len(alerts) > 0 {
		s.state.Mu.Lock()
		s.state.DNSAlerts = append(s.state.DNSAlerts, alerts...)
		s.state.Mu.Unlock()

		if s.alertMgr != nil {
			go s.alertMgr.SendSecurityAlerts(nil, alerts)
		}
	}
}

func (s *Scanner) findSubnet(ip net.IP) string {
	s.subnetsMu.RLock()
	for _, subnet := range s.subnets {
		if subnet.Contains(ip) {
			s.subnetsMu.RUnlock()
			return subnet.String()
		}
	}
	s.subnetsMu.RUnlock()
	s.subnetsV6Mu.RLock()
	defer s.subnetsV6Mu.RUnlock()
	for _, subnet := range s.subnetsV6 {
		if subnet.Contains(ip) {
			return subnet.String()
		}
	}
	return ""
}

// snapshotSubnets returns a copy of the current IPv4 subnet list.
// Callers must not hold s.state.Mu when calling (avoids lock-order inversion).
func (s *Scanner) snapshotSubnets() []*net.IPNet {
	s.subnetsMu.RLock()
	defer s.subnetsMu.RUnlock()
	out := make([]*net.IPNet, len(s.subnets))
	copy(out, s.subnets)
	return out
}

// snapshotSubnetsV6 returns a copy of the current IPv6 subnet list.
// Callers must not hold s.state.Mu when calling (avoids lock-order inversion).
func (s *Scanner) snapshotSubnetsV6() []*net.IPNet {
	s.subnetsV6Mu.RLock()
	defer s.subnetsV6Mu.RUnlock()
	out := make([]*net.IPNet, len(s.subnetsV6))
	copy(out, s.subnetsV6)
	return out
}

// ingestObserved processes passively-observed ARP traffic (IP->MAC) to:
//   - add newly-appeared hosts to the host list, and
//   - discover new /24 subnets not yet scanned, then actively sweep them.
//
// baseline (owned by the calling backgroundARPMonitor goroutine) is updated in
// place so subsequent monitor cycles track the newly-learned hosts for spoofing.
func (s *Scanner) ingestObserved(observed map[string]string, baseline map[string][]string) {
	if len(observed) == 0 {
		return
	}

	localMACStr := ""
	if s.localMAC != nil {
		localMACStr = s.localMAC.String()
	}

	// IPs already tracked as IPv4 hosts.
	s.state.Mu.RLock()
	known := make(map[string]bool)
	for _, h := range s.state.Hosts {
		if h.IPVersion == 4 {
			known[h.IP] = true
		}
	}
	s.state.Mu.RUnlock()

	// ARP carries no netmask, so assume the same prefix length as our own
	// interface (falls back to /24) rather than blindly hardcoding /24.
	prefixLen := netutil.InterfaceIPv4PrefixLen(s.iface)

	var newHosts []models.HostEntry
	var newSubnets []*net.IPNet
	seenNewSubnet := make(map[string]bool)

	for ipStr, macStr := range observed {
		ip := net.ParseIP(ipStr)
		if ip == nil || ip.To4() == nil {
			continue
		}
		// Skip our own IP and any traffic sourced from our own MAC
		// (e.g. the synthesized source IPs we emit while sweeping).
		if s.localIP != nil && ip.Equal(s.localIP) {
			continue
		}
		if macStr == localMACStr {
			continue
		}
		// Skip our own synthetic L2-harvest identities (their probe traffic and
		// adopted source IPs are our own, not real hosts).
		if s.subnetIDs != nil && (s.subnetIDs.IsSyntheticMAC(macStr) || s.subnetIDs.IsSyntheticIP(ipStr)) {
			continue
		}

		// Learn a new subnet if this IP falls outside every known subnet.
		if s.findSubnet(ip) == "" {
			base := ip.Mask(net.CIDRMask(prefixLen, 32))
			cidr := fmt.Sprintf("%s/%d", base.String(), prefixLen)
			if !seenNewSubnet[cidr] {
				if _, ipnet, err := net.ParseCIDR(cidr); err == nil {
					seenNewSubnet[cidr] = true
					newSubnets = append(newSubnets, ipnet)
				}
			}
		}

		// Track baseline for future spoof detection.
		if _, ok := baseline[ipStr]; !ok {
			baseline[ipStr] = []string{macStr}
		}

		if known[ipStr] {
			continue
		}
		known[ipStr] = true
		vendor := "Unknown"
		if mac, err := net.ParseMAC(macStr); err == nil && s.oui != nil {
			vendor = s.oui.Lookup(mac)
		}
		newHosts = append(newHosts, models.HostEntry{
			IP:        ipStr,
			MAC:       macStr,
			Vendor:    vendor,
			IPVersion: 4,
		})
	}

	// Register and sweep any newly-discovered subnets.
	if len(newSubnets) > 0 {
		s.subnetsMu.Lock()
		s.subnets = append(s.subnets, newSubnets...)
		s.subnetsMu.Unlock()
		for _, sn := range newSubnets {
			log.Printf("discovered new subnet via passive ARP: %s", sn)
		}
		go s.sweepSubnets(newSubnets)
	}

	// Add passively-observed hosts (subnet label may have just been learned).
	if len(newHosts) > 0 {
		for i := range newHosts {
			newHosts[i].Subnet = s.findSubnet(net.ParseIP(newHosts[i].IP))
		}
		added := s.addHosts(newHosts)
		if len(added) > 0 {
			s.resolveHostnames()
			if s.alertMgr != nil {
				go s.alertMgr.SendHostAlerts(added)
			}
		}
	}
}

// sweepSubnets discovers hosts in newly-learned subnets and merges them into the
// host list additively. Attached subnets use ARP; remote (routed) subnets use
// L3 probes - never spoofed cross-subnet ARP.
func (s *Scanner) sweepSubnets(subnets []*net.IPNet) {
	if s.localIP == nil || len(subnets) == 0 {
		return
	}
	s.bgScanBegin()
	defer s.bgScanEnd()

	var attached, remote []*net.IPNet
	for _, sn := range subnets {
		if sn.Contains(s.localIP) {
			attached = append(attached, sn)
		} else {
			remote = append(remote, sn)
		}
	}
	if len(attached) > 0 {
		if result, err := protocol.ARPScan(s.iface, s.localIP, s.localMAC, attached, 3*time.Second); err == nil {
			s.mergeARPResult(result)
		} else {
			log.Printf("new-subnet ARP sweep failed: %v", err)
		}
	}
	if len(remote) > 0 {
		s.harvestRemoteMACs(remote)
		s.mergeL3Alive(protocol.L3ProbeScan(remote, s.localIP, 3*time.Second))
	}
}

// harvestRemoteMACs ARP-scans L2-reachable secondary subnets (Case A) from
// per-subnet synthetic identities and merges the recovered IP→MAC pairs. Truly
// routed subnets simply yield no ARP replies and fall through to the L3 probe.
func (s *Scanner) harvestRemoteMACs(remote []*net.IPNet) {
	if res := protocol.HarvestRemoteMACs(s.iface, remote, s.localIP, s.subnetIDs, 3*time.Second); res != nil {
		s.mergeARPResult(res)
	}
}

// probeRemoteSubnets discovers hosts in the routed (non-attached) subnets of the
// given list via L3 probes and merges them.
func (s *Scanner) probeRemoteSubnets(subnets []*net.IPNet) {
	if s.localIP == nil {
		return
	}
	var remote []*net.IPNet
	for _, sn := range subnets {
		if !sn.Contains(s.localIP) {
			remote = append(remote, sn)
		}
	}
	if len(remote) == 0 {
		return
	}
	s.bgScanBegin()
	s.harvestRemoteMACs(remote)
	alive := protocol.L3ProbeScan(remote, s.localIP, 3*time.Second)
	s.bgScanEnd()
	s.mergeL3Alive(alive)
}

// mergeL3Alive turns a set of L3-discovered live IPs into host entries (MAC is
// unknowable across a router) and merges them additively.
func (s *Scanner) mergeL3Alive(alive map[string]bool) {
	if len(alive) == 0 {
		return
	}
	var hosts []models.HostEntry
	for ipStr := range alive {
		ip := net.ParseIP(ipStr)
		if ip == nil || ip.To4() == nil {
			continue
		}
		hosts = append(hosts, models.HostEntry{
			IP:        ipStr,
			MAC:       "",
			Vendor:    "",
			Subnet:    s.findSubnet(ip),
			IPVersion: 4,
		})
	}
	added := s.addHosts(hosts)
	if len(added) > 0 {
		s.resolveHostnames()
		if s.alertMgr != nil {
			go s.alertMgr.SendHostAlerts(added)
		}
	}
}

// mergeARPResult converts an ARPResult into hosts/conflicts and merges them into
// the existing state additively (unlike processARPResults, which rebuilds the
// whole IPv4 host list). Only newly-added entries trigger alerts.
func (s *Scanner) mergeARPResult(result *protocol.ARPResult) {
	result.Mu.Lock()
	var hosts []models.HostEntry
	var conflicts []models.ConflictEntry
	for ipStr, macs := range result.Entries {
		ip := net.ParseIP(ipStr)
		subnet := s.findSubnet(ip)
		mac := macs[0]
		vendor := "Unknown"
		if s.oui != nil {
			vendor = s.oui.Lookup(mac)
		}
		host := models.HostEntry{
			IP:        ipStr,
			MAC:       mac.String(),
			Vendor:    vendor,
			Subnet:    subnet,
			IPVersion: 4,
		}
		if len(macs) > 1 {
			devGroups := netutil.GroupMACsByDevice(macs)
			var macStrs, vendorStrs []string
			for _, m := range macs {
				macStrs = append(macStrs, m.String())
				if s.oui != nil {
					vendorStrs = append(vendorStrs, s.oui.Lookup(m))
				}
			}
			if len(devGroups) == 1 {
				host.IsBond = true
				host.BondMACs = macStrs
				host.BondVendors = vendorStrs
			} else {
				conflicts = append(conflicts, models.ConflictEntry{
					IP:      ipStr,
					MACs:    macStrs,
					Vendors: vendorStrs,
					Subnet:  subnet,
				})
			}
		}
		hosts = append(hosts, host)
	}
	result.Mu.Unlock()

	addedHosts := s.addHosts(hosts)
	addedConflicts := s.addConflicts(conflicts)

	if len(addedHosts) > 0 {
		s.resolveHostnames()
		if s.alertMgr != nil {
			go s.alertMgr.SendHostAlerts(addedHosts)
		}
	}
	if len(addedConflicts) > 0 {
		addedIPs := make(map[string]bool, len(addedConflicts))
		for _, c := range addedConflicts {
			addedIPs[c.IP] = true
		}
		s.reclassifyAndAlert(addedIPs)
	}
}

// ingestObservedV6 processes passively-observed NDP traffic (IP->MAC) to add
// newly-appeared IPv6 hosts and discover new prefixes not yet scanned, then
// actively sweep (NDP multicast) to fill in quiet hosts. Mirrors ingestObserved.
//
// baseline (owned by the calling backgroundNDPMonitor goroutine) is updated in
// place so subsequent monitor cycles track the newly-learned hosts for spoofing.
func (s *Scanner) ingestObservedV6(observed map[string]string, baseline map[string][]string) {
	if len(observed) == 0 {
		return
	}

	localMACStr := ""
	if s.localMAC != nil {
		localMACStr = s.localMAC.String()
	}

	s.state.Mu.RLock()
	known := make(map[string]bool)
	for _, h := range s.state.Hosts {
		if h.IPVersion == 6 {
			known[h.IP] = true
		}
	}
	s.state.Mu.RUnlock()

	prefixLen := netutil.InterfaceIPv6PrefixLen(s.iface)

	var newHosts []models.HostEntry
	var newSubnets []*net.IPNet
	seenNewSubnet := make(map[string]bool)

	for ipStr, macStr := range observed {
		ip := net.ParseIP(ipStr)
		if ip == nil || ip.To4() != nil {
			continue
		}
		// Skip our own addresses and traffic sourced from our own MAC.
		if (s.localIPv6 != nil && ip.Equal(s.localIPv6)) ||
			(s.linkLocalIPv6 != nil && ip.Equal(s.linkLocalIPv6)) {
			continue
		}
		if macStr == localMACStr {
			continue
		}
		// Only track global-unicast addresses (link-local/multicast are noise).
		if !ip.IsGlobalUnicast() {
			continue
		}

		// Learn a new prefix if this IP falls outside every known subnet.
		if s.findSubnet(ip) == "" {
			base := ip.Mask(net.CIDRMask(prefixLen, 128))
			cidr := fmt.Sprintf("%s/%d", base.String(), prefixLen)
			if !seenNewSubnet[cidr] {
				if _, ipnet, err := net.ParseCIDR(cidr); err == nil {
					seenNewSubnet[cidr] = true
					newSubnets = append(newSubnets, ipnet)
				}
			}
		}

		if _, ok := baseline[ipStr]; !ok {
			baseline[ipStr] = []string{macStr}
		}

		if known[ipStr] {
			continue
		}
		known[ipStr] = true
		vendor := "Unknown"
		if mac, err := net.ParseMAC(macStr); err == nil && s.oui != nil {
			vendor = s.oui.Lookup(mac)
		}
		newHosts = append(newHosts, models.HostEntry{
			IP:        ipStr,
			MAC:       macStr,
			Vendor:    vendor,
			IPVersion: 6,
		})
	}

	if len(newSubnets) > 0 {
		s.subnetsV6Mu.Lock()
		s.subnetsV6 = append(s.subnetsV6, newSubnets...)
		s.subnetsV6Mu.Unlock()
		for _, sn := range newSubnets {
			log.Printf("discovered new IPv6 subnet via passive NDP: %s", sn)
		}
		go s.sweepV6()
	}

	if len(newHosts) > 0 {
		for i := range newHosts {
			newHosts[i].Subnet = s.findSubnet(net.ParseIP(newHosts[i].IP))
		}
		added := s.addHosts(newHosts)
		if len(added) > 0 {
			s.resolveHostnames()
			if s.alertMgr != nil {
				go s.alertMgr.SendHostAlerts(added)
			}
		}
	}
}

// sweepV6 runs an NDP multicast scan (which reaches every on-link node) and
// merges newly-discovered IPv6 hosts into the host list.
func (s *Scanner) sweepV6() {
	srcIPv6 := s.localIPv6
	if srcIPv6 == nil {
		srcIPv6 = s.linkLocalIPv6
	}
	if srcIPv6 == nil {
		return
	}
	s.bgScanBegin()
	defer s.bgScanEnd()
	result, err := protocol.NDPScan(s.iface, srcIPv6, s.localMAC, s.snapshotSubnetsV6(), 3*time.Second)
	if err != nil {
		log.Printf("new-subnet NDP sweep failed: %v", err)
		return
	}
	s.mergeNDPResult(result)
}

// mergeNDPResult converts an NDPResult into hosts and merges them additively
// (unlike processNDPResults, which rebuilds the whole IPv6 host list). Only
// newly-added hosts trigger alerts. Link-local addresses are skipped when the
// same MAC already has a global address.
func (s *Scanner) mergeNDPResult(result *protocol.NDPResult) {
	result.Mu.Lock()
	globalMACs := make(map[string]bool)
	for ipStr, macs := range result.Entries {
		ip := net.ParseIP(ipStr)
		if ip != nil && !ip.IsLinkLocalUnicast() {
			for _, m := range macs {
				globalMACs[m.String()] = true
			}
		}
	}

	var hosts []models.HostEntry
	for ipStr, macs := range result.Entries {
		ip := net.ParseIP(ipStr)
		mac := macs[0]
		macStr := mac.String()
		if ip != nil && ip.IsLinkLocalUnicast() && globalMACs[macStr] {
			continue
		}
		vendor := "Unknown"
		if s.oui != nil {
			vendor = s.oui.Lookup(mac)
		}
		host := models.HostEntry{
			IP:        ipStr,
			MAC:       macStr,
			Vendor:    vendor,
			Subnet:    s.findSubnet(ip),
			IPVersion: 6,
		}
		if len(macs) > 1 {
			if devGroups := netutil.GroupMACsByDevice(macs); len(devGroups) == 1 {
				var macStrs, vendorStrs []string
				for _, m := range macs {
					macStrs = append(macStrs, m.String())
					if s.oui != nil {
						vendorStrs = append(vendorStrs, s.oui.Lookup(m))
					}
				}
				host.IsBond = true
				host.BondMACs = macStrs
				host.BondVendors = vendorStrs
			}
		}
		hosts = append(hosts, host)
	}
	result.Mu.Unlock()

	added := s.addHosts(hosts)
	if len(added) > 0 {
		s.resolveHostnames()
		if s.alertMgr != nil {
			go s.alertMgr.SendHostAlerts(added)
		}
	}
}

// addHosts merges hosts into state, adding only IPs not already present.
// Returns the subset that was newly added. The host list is kept sorted by IP.
func (s *Scanner) addHosts(hosts []models.HostEntry) []models.HostEntry {
	if len(hosts) == 0 {
		return nil
	}
	s.state.Mu.Lock()
	defer s.state.Mu.Unlock()

	existing := make(map[string]bool, len(s.state.Hosts))
	for _, h := range s.state.Hosts {
		existing[h.IP] = true
	}
	var added []models.HostEntry
	for _, h := range hosts {
		if existing[h.IP] {
			continue
		}
		existing[h.IP] = true
		s.state.Hosts = append(s.state.Hosts, h)
		added = append(added, h)
	}
	if len(added) > 0 {
		sortHostsByIP(s.state.Hosts)
	}
	return added
}

// addConflicts merges conflict entries into state, adding only IPs not already
// present. Returns the subset that was newly added.
func (s *Scanner) addConflicts(conflicts []models.ConflictEntry) []models.ConflictEntry {
	if len(conflicts) == 0 {
		return nil
	}
	s.state.Mu.Lock()
	defer s.state.Mu.Unlock()

	existing := make(map[string]bool, len(s.state.Conflicts))
	for _, c := range s.state.Conflicts {
		existing[c.IP] = true
	}
	var added []models.ConflictEntry
	for _, c := range conflicts {
		if existing[c.IP] {
			continue
		}
		existing[c.IP] = true
		s.state.Conflicts = append(s.state.Conflicts, c)
		added = append(added, c)
	}
	// Classify synchronously here (cross-IP signals need the full set) so the
	// kind/reason labels are set the moment a conflict is added, independent of
	// any slower downstream work (e.g. hostname resolution).
	if len(added) > 0 {
		classifyConflicts(s.state.Conflicts)
	}
	return added
}

// classifyConflicts labels each multi-MAC entry as a genuine "conflict" or a
// "likely" VIP/bond/SDN pattern, using cross-IP signals so systematic setups are
// not reported as accidental IP collisions. It mutates entries in place.
//
// Downgrade signals (strongest first):
//   - shared_mac: a MAC also answers for another IP → one host holds several IPs
//     (VIP / bond / floating IP).
//   - oui_pair:   the same set of vendor OUIs conflicts on more than one IP → a
//     systematic multi-NIC or VIP deployment, not random collisions.
//   - neutron:    an OpenStack (fa:16:3e) VM MAC alongside another responder → an
//     SDN/overlay ARP responder.
//   - all_laa:    every MAC is locally-administered → virtual NICs (VM/bond).
//
// A genuine accidental collision - two unrelated global-vendor MACs, appearing on
// a single IP with no repeated pattern - keeps kind "conflict".
func classifyConflicts(conflicts []models.ConflictEntry) {
	if len(conflicts) == 0 {
		return
	}

	macIPs := make(map[string]map[string]bool)     // mac -> set of IPs
	ouiSetIPs := make(map[string]map[string]bool)  // sorted OUI-set -> set of IPs
	for _, c := range conflicts {
		macs := lowerMACs(c.MACs)
		for _, m := range macs {
			if macIPs[m] == nil {
				macIPs[m] = make(map[string]bool)
			}
			macIPs[m][c.IP] = true
		}
		key := ouiSetKey(macs)
		if ouiSetIPs[key] == nil {
			ouiSetIPs[key] = make(map[string]bool)
		}
		ouiSetIPs[key][c.IP] = true
	}

	for i := range conflicts {
		c := &conflicts[i]
		macs := lowerMACs(c.MACs)

		sharedMAC := false
		for _, m := range macs {
			if len(macIPs[m]) > 1 {
				sharedMAC = true
				break
			}
		}
		sharedPair := len(ouiSetIPs[ouiSetKey(macs)]) > 1

		allLAA, anyNeutron := true, false
		for _, m := range macs {
			if !isLAAMac(m) {
				allLAA = false
			}
			if strings.HasPrefix(m, "fa:16:3e") {
				anyNeutron = true
			}
		}

		switch {
		case sharedMAC:
			c.Kind, c.Reason = "likely", "shared_mac"
		case sharedPair:
			c.Kind, c.Reason = "likely", "oui_pair"
		case anyNeutron:
			c.Kind, c.Reason = "likely", "neutron"
		case allLAA:
			c.Kind, c.Reason = "likely", "all_laa"
		default:
			c.Kind, c.Reason = "conflict", ""
		}
	}
}

func lowerMACs(macs []string) []string {
	out := make([]string, len(macs))
	for i, m := range macs {
		out[i] = strings.ToLower(m)
	}
	return out
}

// ouiSetKey returns a stable key from the sorted set of distinct 24-bit OUIs in a
// MAC list, so the same vendor combination maps to the same key regardless of the
// device-specific suffix or ordering.
func ouiSetKey(macs []string) string {
	set := make(map[string]bool)
	for _, m := range macs {
		if len(m) >= 8 {
			set[m[:8]] = true
		}
	}
	list := make([]string, 0, len(set))
	for o := range set {
		list = append(list, o)
	}
	sort.Strings(list)
	return strings.Join(list, "|")
}

// isLAAMac reports whether a MAC string's first octet has the
// locally-administered bit set.
func isLAAMac(mac string) bool {
	if len(mac) < 2 {
		return false
	}
	b, err := strconv.ParseUint(mac[:2], 16, 16)
	if err != nil {
		return false
	}
	return byte(b)&0x02 != 0
}

// sortHostsByIP sorts a host slice by IP (IPv4 and IPv6 ordered together).
func sortHostsByIP(hosts []models.HostEntry) {
	sort.Slice(hosts, func(i, j int) bool {
		a := net.ParseIP(hosts[i].IP)
		b := net.ParseIP(hosts[j].IP)
		if a == nil || b == nil {
			return hosts[i].IP < hosts[j].IP
		}
		return bytes.Compare(a.To16(), b.To16()) < 0
	})
}

// lookupVendor resolves a MAC address string to its vendor name
func (s *Scanner) lookupVendor(macStr string) string {
	if s.oui != nil {
		if hw, err := net.ParseMAC(macStr); err == nil {
			return s.oui.Lookup(hw)
		}
	}
	return "Unknown"
}

// backgroundProtocolListeners continuously listens for protocol advertisements
func (s *Scanner) backgroundProtocolListeners() {
	for {
		select {
		case <-s.bgStopCh:
			return
		default:
		}

		var wg sync.WaitGroup
		wg.Add(4)

		var newHSRP []models.HSRPEntry
		var newVRRP []models.VRRPEntry
		var newLLDP []models.LLDPNeighbor
		var newCDP []models.CDPNeighbor
		var protoMu sync.Mutex

		go func() {
			defer wg.Done()
			entries, _ := protocol.ListenHSRP(s.iface.Name, 30*time.Second, s.bgStopCh, s.ipMode)
			if len(entries) > 0 {
				s.state.Mu.Lock()
				before := len(s.state.HSRPEntries)
				s.state.HSRPEntries = deduplicateHSRP(append(s.state.HSRPEntries, entries...))
				after := len(s.state.HSRPEntries)
				s.state.Mu.Unlock()
				if after > before {
					protoMu.Lock()
					newHSRP = entries
					protoMu.Unlock()
				}
			}
		}()

		go func() {
			defer wg.Done()
			entries, _ := protocol.ListenVRRP(s.iface.Name, 30*time.Second, s.bgStopCh, s.ipMode)
			if len(entries) > 0 {
				s.state.Mu.Lock()
				before := len(s.state.VRRPEntries)
				s.state.VRRPEntries = deduplicateVRRP(append(s.state.VRRPEntries, entries...))
				after := len(s.state.VRRPEntries)
				s.state.Mu.Unlock()
				if after > before {
					protoMu.Lock()
					newVRRP = entries
					protoMu.Unlock()
				}
			}
		}()

		go func() {
			defer wg.Done()
			entries, _ := protocol.ListenLLDP(s.iface.Name, 30*time.Second, s.bgStopCh)
			if len(entries) > 0 {
				s.state.Mu.Lock()
				before := len(s.state.LLDPNeighbors)
				s.state.LLDPNeighbors = deduplicateLLDP(append(s.state.LLDPNeighbors, entries...))
				after := len(s.state.LLDPNeighbors)
				s.state.Mu.Unlock()
				if after > before {
					protoMu.Lock()
					newLLDP = entries
					protoMu.Unlock()
				}
			}
		}()

		go func() {
			defer wg.Done()
			entries, _ := protocol.ListenCDP(s.iface.Name, 30*time.Second, s.bgStopCh)
			if len(entries) > 0 {
				s.state.Mu.Lock()
				before := len(s.state.CDPNeighbors)
				s.state.CDPNeighbors = deduplicateCDP(append(s.state.CDPNeighbors, entries...))
				after := len(s.state.CDPNeighbors)
				s.state.Mu.Unlock()
				if after > before {
					protoMu.Lock()
					newCDP = entries
					protoMu.Unlock()
				}
			}
		}()

		wg.Wait()

		if s.alertMgr != nil {
			if len(newHSRP) > 0 || len(newVRRP) > 0 {
				go s.alertMgr.SendProtocolAlerts(newHSRP, newVRRP)
			}
			if len(newLLDP) > 0 || len(newCDP) > 0 {
				go s.alertMgr.SendDiscoveryAlerts(newLLDP, newCDP)
			}
		}
	}
}

// reverifyHostsAndConflicts probes all known IPv4 hosts (and conflicts) and:
//   - removes conflict entries that resolved to a single MAC
//   - removes hosts that have not responded for `maxMisses` consecutive cycles
//   - clears ARPAlerts for resolved IPs
const maxHostMisses = 5

func (s *Scanner) reverifyHostsAndConflicts() {
	s.bgScanBegin()
	defer s.bgScanEnd()
	if s.localIP != nil {
		s.reverifyIPv4()
	}
	if s.linkLocalIPv6 != nil {
		s.reverifyIPv6()
	}
}

func (s *Scanner) reverifyIPv6() {
	// Send NDP multicast and collect responses
	ndpResult, err := protocol.NDPScan(s.iface, s.linkLocalIPv6, s.localMAC, s.snapshotSubnetsV6(), 2*time.Second)
	if err != nil {
		return
	}

	ndpResult.Mu.Lock()
	aliveV6 := make(map[string]bool)
	currentMACs := make(map[string]map[string]bool)
	for ipStr, macs := range ndpResult.Entries {
		aliveV6[ipStr] = true
		set := make(map[string]bool)
		for _, m := range macs {
			set[strings.ToLower(m.String())] = true
		}
		currentMACs[ipStr] = set
	}
	ndpResult.Mu.Unlock()

	s.state.Mu.Lock()
	defer s.state.Mu.Unlock()

	s.hostMissMu.Lock()
	rm := make(map[string]bool)
	for _, h := range s.state.Hosts {
		if h.IPVersion != 6 {
			continue
		}
		if aliveV6[h.IP] {
			delete(s.hostMissCount, h.IP)
			continue
		}
		s.hostMissCount[h.IP]++
		if s.hostMissCount[h.IP] >= maxHostMisses {
			rm[h.IP] = true
			delete(s.hostMissCount, h.IP)
		}
	}
	s.hostMissMu.Unlock()

	if len(rm) > 0 {
		var kept []models.HostEntry
		for _, h := range s.state.Hosts {
			if rm[h.IP] {
				continue
			}
			kept = append(kept, h)
		}
		s.state.Hosts = kept
	}

	// Clean up NDP spoof alerts. Drop an alert when the host was removed, or
	// the flagged (suspicious) MAC no longer advertises that IP.
	var keptAlerts []models.NDPSpoofAlert
	for _, a := range s.state.NDPAlerts {
		stale := rm[a.IP]
		if !stale {
			if set, probed := currentMACs[a.IP]; probed {
				if !set[strings.ToLower(a.NewMAC)] {
					stale = true
				}
			}
		}
		if stale {
			delete(s.emailedNDPKeys, a.IP+":"+a.NewMAC)
			continue
		}
		keptAlerts = append(keptAlerts, a)
	}
	s.state.NDPAlerts = keptAlerts
}

func (s *Scanner) reverifyIPv4() {

	s.state.Mu.RLock()
	var ips []net.IP
	for _, h := range s.state.Hosts {
		if h.IPVersion != 4 {
			continue
		}
		if ip := net.ParseIP(h.IP); ip != nil {
			ips = append(ips, ip)
		}
	}
	for _, c := range s.state.Conflicts {
		if ip := net.ParseIP(c.IP); ip != nil {
			// Avoid duplicate
			already := false
			for _, x := range ips {
				if x.Equal(ip) {
					already = true
					break
				}
			}
			if !already {
				ips = append(ips, ip)
			}
		}
	}
	// Include ARP spoof alert IPs so stale alerts can be reverified/removed
	for _, a := range s.state.ARPAlerts {
		if ip := net.ParseIP(a.IP); ip != nil {
			already := false
			for _, x := range ips {
				if x.Equal(ip) {
					already = true
					break
				}
			}
			if !already {
				ips = append(ips, ip)
			}
		}
	}
	s.state.Mu.RUnlock()

	if len(ips) == 0 {
		return
	}

	result, err := protocol.ProbeIPs(s.iface, s.localIP, s.localMAC, s.snapshotSubnets(), ips, 2*time.Second)
	if err != nil {
		log.Printf("reverify error: %v", err)
		return
	}

	result.Mu.Lock()
	currentMACs := make(map[string]map[string]bool)
	for ipStr, macs := range result.Entries {
		set := make(map[string]bool)
		for _, m := range macs {
			set[strings.ToLower(m.String())] = true
		}
		currentMACs[ipStr] = set
	}
	result.Mu.Unlock()

	// Remote (routed) hosts have no MAC and can't be ARP-probed; re-check their
	// liveness with L3 probes so they aren't wrongly aged out.
	subs := s.snapshotSubnets()
	isAttached := func(ip net.IP) bool {
		for _, sn := range subs {
			if sn.Contains(ip) && s.localIP != nil && sn.Contains(s.localIP) {
				return true
			}
		}
		return false
	}
	var remoteIPs []net.IP
	for _, ip := range ips {
		if !isAttached(ip) {
			remoteIPs = append(remoteIPs, ip)
		}
	}
	aliveL3 := protocol.L3ProbeIPs(remoteIPs, 2*time.Second)
	isLive := func(ip string) bool {
		if _, ok := currentMACs[ip]; ok {
			return true
		}
		return aliveL3[ip]
	}

	s.state.Mu.Lock()
	defer s.state.Mu.Unlock()

	// Update miss counts for IPv4 hosts and decide removals
	s.hostMissMu.Lock()
	removeHost := make(map[string]bool)
	for _, h := range s.state.Hosts {
		if h.IPVersion != 4 {
			continue
		}
		if isLive(h.IP) {
			delete(s.hostMissCount, h.IP)
			continue
		}
		s.hostMissCount[h.IP]++
		if s.hostMissCount[h.IP] >= maxHostMisses {
			removeHost[h.IP] = true
			delete(s.hostMissCount, h.IP)
		}
	}
	s.hostMissMu.Unlock()

	// Resolve conflicts: keep if multiple MACs still respond, or if we got no response at all
	resolved := make(map[string]bool)
	var keptConflicts []models.ConflictEntry
	var resolvedEntries []models.ConflictResolvedEntry
	for _, c := range s.state.Conflicts {
		set, probed := currentMACs[c.IP]
		if !probed || len(set) >= 2 {
			keptConflicts = append(keptConflicts, c)
			continue
		}
		resolved[c.IP] = true

		// Build resolved entry with current MAC info
		var curMAC, curVendor string
		for m := range set {
			curMAC = m
			if s.oui != nil {
				if hw, err := net.ParseMAC(m); err == nil {
					curVendor = s.oui.Lookup(hw)
				}
			}
			break
		}
		// Find where removed MACs went (new IP from host list)
		removedNewIPs := make(map[string]string)
		curLower := strings.ToLower(curMAC)
		for _, m := range c.MACs {
			if strings.ToLower(m) == curLower {
				continue
			}
			// Look up this MAC in host list for its current IP
			mLower := strings.ToLower(m)
			for _, h := range s.state.Hosts {
				if strings.ToLower(h.MAC) == mLower && h.IP != c.IP {
					removedNewIPs[m] = h.IP
					break
				}
			}
		}

		resolvedEntries = append(resolvedEntries, models.ConflictResolvedEntry{
			IP:            c.IP,
			Hostname:      c.Hostname,
			PrevMACs:      c.MACs,
			PrevVendors:   c.Vendors,
			CurrentMAC:    curMAC,
			CurrentVendor: curVendor,
			RemovedNewIPs: removedNewIPs,
			Subnet:        c.Subnet,
		})
	}

	// Apply host removals
	if len(removeHost) > 0 {
		var keptHosts []models.HostEntry
		for _, h := range s.state.Hosts {
			if removeHost[h.IP] {
				continue
			}
			keptHosts = append(keptHosts, h)
		}
		s.state.Hosts = keptHosts
	}

	// Apply conflict removals
	if len(resolved) > 0 {
		s.state.Conflicts = keptConflicts
	}

	// Clean up ARP spoof alerts. Drop an alert when any of:
	//   - its IP's conflict has resolved,
	//   - the host was removed for being unresponsive, or
	//   - the flagged (suspicious) MAC no longer answers for that IP.
	var keptAlerts []models.ARPSpoofAlert
	for _, a := range s.state.ARPAlerts {
		stale := resolved[a.IP] || removeHost[a.IP]
		if !stale {
			if set, probed := currentMACs[a.IP]; probed {
				if !set[strings.ToLower(a.NewMAC)] {
					stale = true
				}
			}
		}
		if stale {
			delete(s.emailedARPKeys, a.IP+":"+a.NewMAC)
			continue
		}
		keptAlerts = append(keptAlerts, a)
	}
	s.state.ARPAlerts = keptAlerts

	if len(resolved) > 0 && s.alertMgr != nil && len(resolvedEntries) > 0 {
		go s.alertMgr.SendConflictResolvedAlerts(resolvedEntries)
	}
}

// backgroundARPMonitor continuously monitors ARP traffic for spoofing
func (s *Scanner) backgroundARPMonitor() {
	if s.arpResult == nil {
		return
	}

	// Build baseline IP->MAC mapping (all known IPs, using all observed MACs)
	baseline := make(map[string][]string)
	s.arpResult.Mu.Lock()
	for ip, macs := range s.arpResult.Entries {
		for _, m := range macs {
			baseline[ip] = append(baseline[ip], m.String())
		}
	}
	s.arpResult.Mu.Unlock()

	// Find gateway IP (routing table first, then DHCP)
	gatewayIP := netutil.GetDefaultGateway()
	if gatewayIP == "" {
		s.state.Mu.RLock()
		for _, srv := range s.state.DHCPServers {
			if srv.Router != "" {
				gatewayIP = srv.Router
				break
			}
		}
		s.state.Mu.RUnlock()
	}

	cycle := 0
	for {
		select {
		case <-s.bgStopCh:
			return
		default:
		}

		// Every 6 cycles (~30s), re-verify hosts and conflicts
		cycle++
		if cycle%6 == 0 {
			s.reverifyHostsAndConflicts()
		}

		alerts, observed, err := protocol.MonitorARP(s.iface.Name, baseline, gatewayIP, 5*time.Second, s.bgStopCh)
		if err != nil {
			log.Printf("ARP monitor error: %v", err)
			continue
		}

		// Passively learn newly-appeared hosts and subnets from observed traffic.
		s.ingestObserved(observed, baseline)

		if len(alerts) > 0 {
			var newARPAlerts []models.ARPSpoofAlert
			s.state.Mu.Lock()
			for _, a := range alerts {
				key := a.IP + ":" + a.NewMAC
				merged := false
				for i := range s.state.ARPAlerts {
					eKey := s.state.ARPAlerts[i].IP + ":" + s.state.ARPAlerts[i].NewMAC
					if eKey == key {
						s.state.ARPAlerts[i].Count += a.Count
						s.state.ARPAlerts[i].Timestamp = a.Timestamp
						merged = true
						break
					}
				}
				if !merged {
					a.Subnet = s.findSubnet(net.ParseIP(a.IP))
					for _, m := range a.OldMACs {
						a.OldVendors = append(a.OldVendors, s.lookupVendor(m))
					}
					a.NewVendor = s.lookupVendor(a.NewMAC)
					var conflictMACs []string
					for _, m := range a.OldMACs {
						conflictMACs = append(conflictMACs, strings.ToLower(m))
					}
					conflictMACs = append(conflictMACs, strings.ToLower(a.NewMAC))
					conflictVendors := append(append([]string{}, a.OldVendors...), a.NewVendor)
					s.state.ARPAlerts = append(s.state.ARPAlerts, a)
					// Skip conflict if all MACs are identical (duplicate ARP replies, not real conflict)
					allSame := true
					for _, m := range conflictMACs {
						if m != conflictMACs[0] {
							allSame = false
							break
						}
					}
					if !allSame {
						// Check if conflict already exists for this IP
						exists := false
						for _, c := range s.state.Conflicts {
							if c.IP == a.IP {
								exists = true
								break
							}
						}
						if !exists {
							s.state.Conflicts = append(s.state.Conflicts, models.ConflictEntry{
								IP:      a.IP,
								MACs:    conflictMACs,
								Vendors: conflictVendors,
								Subnet:  a.Subnet,
							})
							classifyConflicts(s.state.Conflicts)
						}
					}
					if !s.emailedARPKeys[key] {
						s.emailedARPKeys[key] = true
						newARPAlerts = append(newARPAlerts, a)
					}
				}
			}
			s.state.Mu.Unlock()
			if s.alertMgr != nil && len(newARPAlerts) > 0 {
				go s.alertMgr.SendSecurityAlerts(newARPAlerts, nil)
			}
		}
	}
}

// processNDPResults converts NDPResult into Hosts (IPv6)
func (s *Scanner) processNDPResults(result *protocol.NDPResult) {
	result.Mu.Lock()
	defer result.Mu.Unlock()

	// Build set of MACs that have a global (non-link-local) address
	globalMACs := make(map[string]bool)
	for ipStr, macs := range result.Entries {
		ip := net.ParseIP(ipStr)
		if ip != nil && !ip.IsLinkLocalUnicast() {
			for _, m := range macs {
				globalMACs[m.String()] = true
			}
		}
	}

	var hosts []models.HostEntry

	for ipStr, macs := range result.Entries {
		ip := net.ParseIP(ipStr)
		mac := macs[0]
		macStr := mac.String()

		// Skip link-local if this MAC already has a global address
		if ip != nil && ip.IsLinkLocalUnicast() && globalMACs[macStr] {
			continue
		}

		vendor := "Unknown"
		if s.oui != nil {
			vendor = s.oui.Lookup(mac)
		}

		host := models.HostEntry{
			IP:        ipStr,
			MAC:       macStr,
			Vendor:    vendor,
			Subnet:    s.findSubnet(ip),
			IPVersion: 6,
		}

		if len(macs) > 1 {
			devGroups := netutil.GroupMACsByDevice(macs)
			if len(devGroups) == 1 {
				var macStrs, vendorStrs []string
				for _, m := range macs {
					macStrs = append(macStrs, m.String())
					if s.oui != nil {
						vendorStrs = append(vendorStrs, s.oui.Lookup(m))
					}
				}
				host.IsBond = true
				host.BondMACs = macStrs
				host.BondVendors = vendorStrs
			}
		}

		hosts = append(hosts, host)
	}

	// Sort by IP
	ips := make([]string, len(hosts))
	for i, h := range hosts {
		ips[i] = h.IP
	}
	netutil.SortIPStrings(ips)
	ipIndex := make(map[string]int)
	for i, ip := range ips {
		ipIndex[ip] = i
	}
	sorted := make([]models.HostEntry, len(hosts))
	for _, h := range hosts {
		sorted[ipIndex[h.IP]] = h
	}

	s.state.Mu.Lock()
	// Preserve hosts from other IP versions (e.g. IPv4 from ARP)
	var keep []models.HostEntry
	for _, h := range s.state.Hosts {
		if h.IPVersion != 6 {
			keep = append(keep, h)
		}
	}
	s.state.Hosts = append(keep, sorted...)
	s.state.Mu.Unlock()
}

// processDHCPv6Results converts DHCPv6ServerInfo to DHCPv6ServerJSON
func (s *Scanner) processDHCPv6Results(servers []models.DHCPv6ServerInfo) {
	var result []models.DHCPv6ServerJSON
	for _, srv := range servers {
		entry := models.DHCPv6ServerJSON{
			Preference:    srv.Preference,
			ValidLifetime: srv.ValidLifetime,
		}
		if srv.ServerIP != nil {
			entry.ServerIP = srv.ServerIP.String()
		}
		if srv.ServerMAC != nil {
			entry.ServerMAC = srv.ServerMAC.String()
			if s.oui != nil {
				entry.Vendor = s.oui.Lookup(srv.ServerMAC)
			}
		}
		for _, dns := range srv.DNSServers {
			entry.DNSServers = append(entry.DNSServers, dns.String())
		}
		entry.DomainSearch = srv.DomainSearch
		result = append(result, entry)
	}

	s.state.Mu.Lock()
	s.state.DHCPv6Servers = result
	s.state.Mu.Unlock()

	if s.alertMgr != nil && len(result) > 0 {
		go s.alertMgr.SendDHCPv6Alerts(result)
	}
}

// backgroundNDPMonitor continuously monitors NDP traffic for spoofing
func (s *Scanner) backgroundNDPMonitor() {
	if s.ndpResult == nil {
		return
	}

	baseline := make(map[string][]string)
	s.ndpResult.Mu.Lock()
	for ip, macs := range s.ndpResult.Entries {
		for _, m := range macs {
			baseline[ip] = append(baseline[ip], m.String())
		}
	}
	s.ndpResult.Mu.Unlock()

	gatewayIPv6 := netutil.GetDefaultGatewayV6()

	for {
		select {
		case <-s.bgStopCh:
			return
		default:
		}

		alerts, observed, err := protocol.MonitorNDP(s.iface.Name, baseline, gatewayIPv6, 5*time.Second, s.bgStopCh)
		if err != nil {
			log.Printf("NDP monitor error: %v", err)
			continue
		}

		// Passively learn newly-appeared IPv6 hosts and subnets.
		s.ingestObservedV6(observed, baseline)

		if len(alerts) > 0 {
			var newNDPAlerts []models.NDPSpoofAlert
			s.state.Mu.Lock()
			for _, a := range alerts {
				key := a.IP + ":" + a.NewMAC
				merged := false
				for i := range s.state.NDPAlerts {
					eKey := s.state.NDPAlerts[i].IP + ":" + s.state.NDPAlerts[i].NewMAC
					if eKey == key {
						s.state.NDPAlerts[i].Count += a.Count
						s.state.NDPAlerts[i].Timestamp = a.Timestamp
						merged = true
						break
					}
				}
				if !merged {
					for _, m := range a.OldMACs {
						a.OldVendors = append(a.OldVendors, s.lookupVendor(m))
					}
					a.NewVendor = s.lookupVendor(a.NewMAC)
					s.state.NDPAlerts = append(s.state.NDPAlerts, a)
					if !s.emailedNDPKeys[key] {
						s.emailedNDPKeys[key] = true
						newNDPAlerts = append(newNDPAlerts, a)
					}
				}
			}
			s.state.Mu.Unlock()
			if s.alertMgr != nil && len(newNDPAlerts) > 0 {
				go s.alertMgr.SendNDPAlerts(newNDPAlerts)
			}
		}
	}
}

// Deduplication helpers
func deduplicateHSRP(entries []models.HSRPEntry) []models.HSRPEntry {
	seen := make(map[string]int)
	for i, e := range entries {
		key := fmt.Sprintf("%d-%d-%s", e.Version, e.Group, e.SourceIP)
		if idx, ok := seen[key]; ok {
			entries[idx] = e
		} else {
			seen[key] = i
		}
	}
	var result []models.HSRPEntry
	added := make(map[string]bool)
	for _, e := range entries {
		key := fmt.Sprintf("%d-%d-%s", e.Version, e.Group, e.SourceIP)
		if !added[key] {
			added[key] = true
			result = append(result, e)
		}
	}
	return result
}

func deduplicateVRRP(entries []models.VRRPEntry) []models.VRRPEntry {
	seen := make(map[string]int)
	for i, e := range entries {
		key := fmt.Sprintf("%d-%s", e.RouterID, e.SourceIP)
		if idx, ok := seen[key]; ok {
			entries[idx] = e
		} else {
			seen[key] = i
		}
	}
	var result []models.VRRPEntry
	added := make(map[string]bool)
	for _, e := range entries {
		key := fmt.Sprintf("%d-%s", e.RouterID, e.SourceIP)
		if !added[key] {
			added[key] = true
			result = append(result, e)
		}
	}
	return result
}

func deduplicateLLDP(entries []models.LLDPNeighbor) []models.LLDPNeighbor {
	seen := make(map[string]int)
	for i, e := range entries {
		key := e.ChassisID + "-" + e.PortID
		if idx, ok := seen[key]; ok {
			entries[idx] = e
		} else {
			seen[key] = i
		}
	}
	var result []models.LLDPNeighbor
	added := make(map[string]bool)
	for _, e := range entries {
		key := e.ChassisID + "-" + e.PortID
		if !added[key] {
			added[key] = true
			result = append(result, e)
		}
	}
	return result
}

func deduplicateCDP(entries []models.CDPNeighbor) []models.CDPNeighbor {
	seen := make(map[string]int)
	for i, e := range entries {
		key := e.DeviceID + "-" + e.PortID
		if idx, ok := seen[key]; ok {
			entries[idx] = e
		} else {
			seen[key] = i
		}
	}
	var result []models.CDPNeighbor
	added := make(map[string]bool)
	for _, e := range entries {
		key := e.DeviceID + "-" + e.PortID
		if !added[key] {
			added[key] = true
			result = append(result, e)
		}
	}
	return result
}
