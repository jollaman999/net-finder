package scanner

import (
	"fmt"
	"log"
	"net"
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
	iface    *net.Interface
	localIP  net.IP
	localMAC net.HardwareAddr
	subnets  []*net.IPNet
	oui      *oui.OUIDatabase
	alertMgr *alert.AlertManager

	state models.ScanState

	stopCh   chan struct{}
	bgStopCh chan struct{}
	running  bool
	runMu    sync.Mutex

	arpResult      *protocol.ARPResult
	hostnameMap    map[string]string
	hostnameMu     sync.RWMutex
	emailedARPKeys map[string]bool
}

// NewScanner creates a new Scanner instance
func NewScanner(iface *net.Interface, localIP net.IP, localMAC net.HardwareAddr, subnets []*net.IPNet, alertMgr *alert.AlertManager) *Scanner {
	return &Scanner{
		iface:    iface,
		localIP:  localIP,
		localMAC: localMAC,
		subnets:  subnets,
		alertMgr: alertMgr,
		state: models.ScanState{
			Status: "idle",
		},
		hostnameMap:    make(map[string]string),
		emailedARPKeys: make(map[string]bool),
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
	s.state.Mu.RLock()
	defer s.state.Mu.RUnlock()
	subnetStrs := make([]string, len(s.subnets))
	for i, sn := range s.subnets {
		subnetStrs[i] = sn.String()
	}
	netutil.SortCIDRStrings(subnetStrs)
	return map[string]interface{}{
		"status":   s.state.Status,
		"progress": s.state.Progress,
		"subnets":  subnetStrs,
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
				if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
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

	s.state.Mu.Lock()
	s.state.Status = "running"
	s.state.Hosts = nil
	s.state.Conflicts = nil
	s.state.DHCPServers = nil
	s.state.HSRPEntries = nil
	s.state.VRRPEntries = nil
	s.state.LLDPNeighbors = nil
	s.state.CDPNeighbors = nil
	s.state.Hostnames = nil
	s.state.ARPAlerts = nil
	s.state.DNSAlerts = nil
	s.state.Mu.Unlock()

	// Phase 1: Load OUI (0-5%)
	s.setProgress("oui_loading", 0, 0)
	if s.stopped() {
		return
	}

	ouiDB, err := oui.LoadOUI()
	if err != nil {
		log.Printf("OUI 로드 실패: %v", err)
		ouiDB = &oui.OUIDatabase{
			Vendors: make(map[string]string),
		}
	}
	s.oui = ouiDB
	s.setProgress("oui_done", 5, len(ouiDB.Vendors))
	if s.stopped() {
		return
	}

	// All phases run in parallel after OUI load
	s.setProgress("scan_parallel", 10, 0)

	var scanWg sync.WaitGroup

	// ── ARP Scan → Hostname Resolution (parallel branch 1) ──
	scanWg.Add(1)
	go func() {
		defer scanWg.Done()
		result, err := protocol.ARPScan(s.iface, s.localIP, s.localMAC, s.subnets, 3*time.Second)
		if err != nil {
			log.Printf("ARP 스캔 실패: %v", err)
			return
		}
		s.arpResult = result
		s.processARPResults(result)
		s.setProgress("scan_arp_done", 30, len(s.GetHosts()))

		if s.stopped() {
			return
		}
		// Hostname resolution immediately after ARP
		s.resolveHostnames()
	}()

	// ── DHCP Detection → DNS Spoofing Check (parallel branch 2) ──
	scanWg.Add(1)
	go func() {
		defer scanWg.Done()
		servers, err := protocol.DetectDHCP(s.iface, s.localMAC, 5*time.Second)
		if err != nil {
			log.Printf("DHCP 감지 실패: %v", err)
			return
		}
		s.processDHCPResults(servers)

		if s.stopped() {
			return
		}
		// DNS spoofing check immediately after DHCP
		s.checkDNSSpoofing()
	}()

	// ── Protocol Listeners: HSRP/VRRP/LLDP/CDP (parallel branch 3) ──
	scanWg.Add(4)
	go func() {
		defer scanWg.Done()
		entries, err := protocol.ListenHSRP(s.iface.Name, 30*time.Second, s.stopCh)
		if err != nil {
			log.Printf("HSRP 리스너 오류: %v", err)
			return
		}
		s.state.Mu.Lock()
		s.state.HSRPEntries = append(s.state.HSRPEntries, entries...)
		s.state.Mu.Unlock()
	}()
	go func() {
		defer scanWg.Done()
		entries, err := protocol.ListenVRRP(s.iface.Name, 30*time.Second, s.stopCh)
		if err != nil {
			log.Printf("VRRP 리스너 오류: %v", err)
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
			log.Printf("LLDP 리스너 오류: %v", err)
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
			log.Printf("CDP 리스너 오류: %v", err)
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

	s.setProgress("scan_done", 100, 0)
	s.state.Mu.Lock()
	s.state.Status = "done"
	s.state.Mu.Unlock()

	// Start background listeners
	go s.backgroundProtocolListeners()
	go s.backgroundARPMonitor()
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
			IP:     ipStr,
			MAC:    strings.ToUpper(mac.String()),
			Vendor: vendor,
			Subnet: subnet,
		}

		// Multiple MACs → check if bond or real conflict
		if len(macs) > 1 {
			devGroups := netutil.GroupMACsByDevice(macs)
			isBond := len(devGroups) == 1

			var macStrs []string
			var vendorStrs []string
			for _, m := range macs {
				macStrs = append(macStrs, strings.ToUpper(m.String()))
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
	s.state.Hosts = sorted
	s.state.Conflicts = conflicts
	s.state.Mu.Unlock()

	// Send alerts for discovered hosts
	if s.alertMgr != nil && len(sorted) > 0 {
		go s.alertMgr.SendHostAlerts(sorted)
	}

	// Send alerts for detected conflicts (grouped by subnet)
	if s.alertMgr != nil && len(conflicts) > 0 {
		go s.alertMgr.SendConflictAlerts(conflicts)
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
			entry.ServerMAC = strings.ToUpper(srv.ServerMAC.String())
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

// resolveHostnames resolves DNS PTR for all discovered hosts
func (s *Scanner) resolveHostnames() {
	s.state.Mu.RLock()
	hostsCopy := make([]models.HostEntry, len(s.state.Hosts))
	copy(hostsCopy, s.state.Hosts)
	s.state.Mu.RUnlock()

	var ips []string
	for _, h := range hostsCopy {
		ips = append(ips, h.IP)
	}

	entries := hostname.ResolveHostnames(ips)

	// Build hostname map
	s.hostnameMu.Lock()
	for _, e := range entries {
		s.hostnameMap[e.IP] = e.Hostname
	}
	s.hostnameMu.Unlock()

	// Update hosts and conflicts with hostnames
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
	s.hostnameMu.RUnlock()
	s.state.Hostnames = entries
	s.state.Mu.Unlock()
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
	for _, subnet := range s.subnets {
		if subnet.Contains(ip) {
			return subnet.String()
		}
	}
	return ""
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
			entries, _ := protocol.ListenHSRP(s.iface.Name, 30*time.Second, s.bgStopCh)
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
			entries, _ := protocol.ListenVRRP(s.iface.Name, 30*time.Second, s.bgStopCh)
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

	for {
		select {
		case <-s.bgStopCh:
			return
		default:
		}

		alerts, err := protocol.MonitorARP(s.iface.Name, baseline, gatewayIP, 5*time.Second, s.bgStopCh)
		if err != nil {
			log.Printf("ARP 모니터 오류: %v", err)
			continue
		}
		if len(alerts) > 0 {
			var newConflicts []models.ConflictEntry
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
					s.state.ARPAlerts = append(s.state.ARPAlerts, a)
					newConflicts = append(newConflicts, models.ConflictEntry{
						IP:     a.IP,
						MACs:   []string{a.OldMAC, a.NewMAC},
						Subnet: a.Subnet,
					})
					if !s.emailedARPKeys[key] {
						s.emailedARPKeys[key] = true
						newARPAlerts = append(newARPAlerts, a)
					}
				}
			}
			s.state.Mu.Unlock()
			if s.alertMgr != nil && len(newConflicts) > 0 {
				go s.alertMgr.SendConflictAlerts(newConflicts)
			}
			if s.alertMgr != nil && len(newARPAlerts) > 0 {
				go s.alertMgr.SendSecurityAlerts(newARPAlerts, nil)
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
