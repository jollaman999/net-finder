package main

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// ProgressInfo represents scan progress
type ProgressInfo struct {
	Phase   string `json:"phase"`
	Percent int    `json:"percent"`
	Count   int    `json:"count,omitempty"`
}

// HostEntry represents a discovered host
type HostEntry struct {
	IP          string   `json:"ip"`
	Hostname    string   `json:"hostname"`
	MAC         string   `json:"mac"`
	Vendor      string   `json:"vendor"`
	Subnet      string   `json:"subnet"`
	IsBond      bool     `json:"isBond,omitempty"`
	BondMACs    []string `json:"bondMACs,omitempty"`
	BondVendors []string `json:"bondVendors,omitempty"`
}

// ConflictEntry represents an IP conflict
type ConflictEntry struct {
	IP       string   `json:"ip"`
	Hostname string   `json:"hostname"`
	MACs     []string `json:"macs"`
	Vendors  []string `json:"vendors"`
	Subnet   string   `json:"subnet"`
}

// DHCPServerJSON is the JSON-friendly DHCP server info
type DHCPServerJSON struct {
	ServerIP   string   `json:"serverIP"`
	ServerMAC  string   `json:"serverMAC"`
	Vendor     string   `json:"vendor"`
	OfferedIP  string   `json:"offeredIP"`
	SubnetMask string   `json:"subnetMask"`
	Router     string   `json:"router"`
	DNS        []string `json:"dns"`
	LeaseTime  uint32   `json:"leaseTime"`
}

// HSRPEntry represents an HSRP advertisement
type HSRPEntry struct {
	Version   int    `json:"version"`
	Group     int    `json:"group"`
	Priority  int    `json:"priority"`
	State     string `json:"state"`
	VirtualIP string `json:"virtualIP"`
	HelloTime int    `json:"helloTime"`
	HoldTime  int    `json:"holdTime"`
	SourceIP  string `json:"sourceIP"`
	SourceMAC string `json:"sourceMAC"`
	Timestamp string `json:"timestamp"`
}

// VRRPEntry represents a VRRP advertisement
type VRRPEntry struct {
	Version     int      `json:"version"`
	RouterID    int      `json:"routerID"`
	Priority    int      `json:"priority"`
	IPAddresses []string `json:"ipAddresses"`
	AdverInt    int      `json:"adverInt"`
	SourceIP    string   `json:"sourceIP"`
	SourceMAC   string   `json:"sourceMAC"`
	Timestamp   string   `json:"timestamp"`
}

// LLDPNeighbor represents an LLDP neighbor
type LLDPNeighbor struct {
	ChassisID string `json:"chassisID"`
	PortID    string `json:"portID"`
	SysName   string `json:"sysName"`
	SysDesc   string `json:"sysDesc"`
	MgmtAddr  string `json:"mgmtAddr"`
	TTL       int    `json:"ttl"`
	SourceMAC string `json:"sourceMAC"`
	Timestamp string `json:"timestamp"`
}

// CDPNeighbor represents a CDP neighbor
type CDPNeighbor struct {
	DeviceID   string   `json:"deviceID"`
	Addresses  []string `json:"addresses"`
	PortID     string   `json:"portID"`
	Platform   string   `json:"platform"`
	Version    string   `json:"version"`
	NativeVLAN int      `json:"nativeVLAN"`
	SourceMAC  string   `json:"sourceMAC"`
	Timestamp  string   `json:"timestamp"`
}

// HostnameEntry maps IP to hostname
type HostnameEntry struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
}

// ARPSpoofAlert represents an ARP spoofing alert
type ARPSpoofAlert struct {
	IP        string `json:"ip"`
	OldMAC    string `json:"oldMAC"`
	NewMAC    string `json:"newMAC"`
	AlertType string `json:"alertType"`
	Severity  string `json:"severity"`
	Message   string `json:"message"`
	Count     int    `json:"count"`
	FirstSeen string `json:"firstSeen"`
	Timestamp string `json:"timestamp"`
}

// DNSSpoofAlert represents a DNS spoofing alert
type DNSSpoofAlert struct {
	Domain    string `json:"domain"`
	Server1   string `json:"server1"`
	Response1 string `json:"response1"`
	Server2   string `json:"server2"`
	Response2 string `json:"response2"`
	AlertType string `json:"alertType"`
	Severity  string `json:"severity"`
	Message   string `json:"message"`
	Timestamp string `json:"timestamp"`
}

// ScanState holds all scan results
type ScanState struct {
	mu            sync.RWMutex
	Status        string           `json:"status"`
	Progress      ProgressInfo     `json:"progress"`
	Hosts         []HostEntry      `json:"hosts"`
	Conflicts     []ConflictEntry  `json:"conflicts"`
	DHCPServers   []DHCPServerJSON `json:"dhcpServers"`
	HSRPEntries   []HSRPEntry      `json:"hsrpEntries"`
	VRRPEntries   []VRRPEntry      `json:"vrrpEntries"`
	LLDPNeighbors []LLDPNeighbor   `json:"lldpNeighbors"`
	CDPNeighbors  []CDPNeighbor    `json:"cdpNeighbors"`
	Hostnames     []HostnameEntry  `json:"hostnames"`
	ARPAlerts     []ARPSpoofAlert  `json:"arpAlerts"`
	DNSAlerts     []DNSSpoofAlert  `json:"dnsAlerts"`
}

// InterfaceInfo for the API
type InterfaceInfo struct {
	Name    string   `json:"name"`
	MAC     string   `json:"mac"`
	IPs     []string `json:"ips"`
	Up      bool     `json:"up"`
	Current bool     `json:"current"`
}

// Scanner orchestrates all scanning operations
type Scanner struct {
	iface    *net.Interface
	localIP  net.IP
	localMAC net.HardwareAddr
	subnets  []*net.IPNet
	oui      *OUIDatabase
	alertMgr *AlertManager

	state ScanState

	stopCh  chan struct{}
	bgStopCh chan struct{}
	running bool
	runMu   sync.Mutex

	arpResult   *ARPResult
	hostnameMap map[string]string
	hostnameMu  sync.RWMutex
}

// NewScanner creates a new Scanner instance
func NewScanner(iface *net.Interface, localIP net.IP, localMAC net.HardwareAddr, subnets []*net.IPNet) *Scanner {
	return &Scanner{
		iface:    iface,
		localIP:  localIP,
		localMAC: localMAC,
		subnets:  subnets,
		state: ScanState{
			Status: "idle",
		},
		hostnameMap: make(map[string]string),
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
	s.state.mu.Lock()
	s.state.Status = "idle"
	s.state.Progress = ProgressInfo{}
	s.state.mu.Unlock()
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
	s.state.mu.Lock()
	s.state.Progress = ProgressInfo{
		Phase:   phase,
		Percent: percent,
		Count:   count,
	}
	s.state.mu.Unlock()
}

// GetStatus returns current scan status and progress
func (s *Scanner) GetStatus() map[string]interface{} {
	s.state.mu.RLock()
	defer s.state.mu.RUnlock()
	return map[string]interface{}{
		"status":   s.state.Status,
		"progress": s.state.Progress,
	}
}

// GetHosts returns the host list
func (s *Scanner) GetHosts() []HostEntry {
	s.state.mu.RLock()
	defer s.state.mu.RUnlock()
	if s.state.Hosts == nil {
		return []HostEntry{}
	}
	return s.state.Hosts
}

// GetConflicts returns conflict entries
func (s *Scanner) GetConflicts() []ConflictEntry {
	s.state.mu.RLock()
	defer s.state.mu.RUnlock()
	if s.state.Conflicts == nil {
		return []ConflictEntry{}
	}
	return s.state.Conflicts
}

// GetDHCPServers returns detected DHCP servers
func (s *Scanner) GetDHCPServers() []DHCPServerJSON {
	s.state.mu.RLock()
	defer s.state.mu.RUnlock()
	if s.state.DHCPServers == nil {
		return []DHCPServerJSON{}
	}
	return s.state.DHCPServers
}

// GetHSRP returns HSRP entries
func (s *Scanner) GetHSRP() []HSRPEntry {
	s.state.mu.RLock()
	defer s.state.mu.RUnlock()
	if s.state.HSRPEntries == nil {
		return []HSRPEntry{}
	}
	return s.state.HSRPEntries
}

// GetVRRP returns VRRP entries
func (s *Scanner) GetVRRP() []VRRPEntry {
	s.state.mu.RLock()
	defer s.state.mu.RUnlock()
	if s.state.VRRPEntries == nil {
		return []VRRPEntry{}
	}
	return s.state.VRRPEntries
}

// GetLLDP returns LLDP neighbors
func (s *Scanner) GetLLDP() []LLDPNeighbor {
	s.state.mu.RLock()
	defer s.state.mu.RUnlock()
	if s.state.LLDPNeighbors == nil {
		return []LLDPNeighbor{}
	}
	return s.state.LLDPNeighbors
}

// GetCDP returns CDP neighbors
func (s *Scanner) GetCDP() []CDPNeighbor {
	s.state.mu.RLock()
	defer s.state.mu.RUnlock()
	if s.state.CDPNeighbors == nil {
		return []CDPNeighbor{}
	}
	return s.state.CDPNeighbors
}

// GetHostnames returns hostname entries
func (s *Scanner) GetHostnames() []HostnameEntry {
	s.state.mu.RLock()
	defer s.state.mu.RUnlock()
	if s.state.Hostnames == nil {
		return []HostnameEntry{}
	}
	return s.state.Hostnames
}

// GetARPAlerts returns ARP spoof alerts
func (s *Scanner) GetARPAlerts() []ARPSpoofAlert {
	s.state.mu.RLock()
	defer s.state.mu.RUnlock()
	if s.state.ARPAlerts == nil {
		return []ARPSpoofAlert{}
	}
	return s.state.ARPAlerts
}

// GetDNSAlerts returns DNS spoof alerts
func (s *Scanner) GetDNSAlerts() []DNSSpoofAlert {
	s.state.mu.RLock()
	defer s.state.mu.RUnlock()
	if s.state.DNSAlerts == nil {
		return []DNSSpoofAlert{}
	}
	return s.state.DNSAlerts
}

// GetInterfaces returns available network interfaces
func GetInterfaces(currentIface string) []InterfaceInfo {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	var result []InterfaceInfo
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if len(iface.HardwareAddr) == 0 {
			continue
		}

		info := InterfaceInfo{
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

	s.state.mu.Lock()
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
	s.state.mu.Unlock()

	// Phase 1: Load OUI (0-5%)
	s.setProgress("oui_loading", 0, 0)
	if s.stopped() {
		return
	}

	oui, err := LoadOUI()
	if err != nil {
		log.Printf("OUI 로드 실패: %v", err)
		oui = &OUIDatabase{
			Vendors:  make(map[string]string),
			prefix2:  make(map[[2]byte]string),
			apiCache: make(map[string]string),
		}
	}
	s.oui = oui
	s.setProgress("oui_done", 5, len(oui.Vendors))
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
		result, err := ARPScan(s.iface, s.localIP, s.localMAC, s.subnets, 3*time.Second)
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
		servers, err := DetectDHCP(s.iface, s.localMAC, 5*time.Second)
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
		entries, err := ListenHSRP(s.iface.Name, 30*time.Second, s.stopCh)
		if err != nil {
			log.Printf("HSRP 리스너 오류: %v", err)
			return
		}
		s.state.mu.Lock()
		s.state.HSRPEntries = append(s.state.HSRPEntries, entries...)
		s.state.mu.Unlock()
	}()
	go func() {
		defer scanWg.Done()
		entries, err := ListenVRRP(s.iface.Name, 30*time.Second, s.stopCh)
		if err != nil {
			log.Printf("VRRP 리스너 오류: %v", err)
			return
		}
		s.state.mu.Lock()
		s.state.VRRPEntries = append(s.state.VRRPEntries, entries...)
		s.state.mu.Unlock()
	}()
	go func() {
		defer scanWg.Done()
		entries, err := ListenLLDP(s.iface.Name, 30*time.Second, s.stopCh)
		if err != nil {
			log.Printf("LLDP 리스너 오류: %v", err)
			return
		}
		s.state.mu.Lock()
		s.state.LLDPNeighbors = append(s.state.LLDPNeighbors, entries...)
		s.state.mu.Unlock()
	}()
	go func() {
		defer scanWg.Done()
		entries, err := ListenCDP(s.iface.Name, 30*time.Second, s.stopCh)
		if err != nil {
			log.Printf("CDP 리스너 오류: %v", err)
			return
		}
		s.state.mu.Lock()
		s.state.CDPNeighbors = append(s.state.CDPNeighbors, entries...)
		s.state.mu.Unlock()
	}()

	scanWg.Wait()

	if s.stopped() {
		return
	}

	s.setProgress("scan_done", 100, 0)
	s.state.mu.Lock()
	s.state.Status = "done"
	s.state.mu.Unlock()

	// Start background listeners
	go s.backgroundProtocolListeners()
	go s.backgroundARPMonitor()
}

// processARPResults converts ARPResult into Hosts and Conflicts
// All discovered IPs go into Hosts. Only real conflicts (not bonds) go into Conflicts.
func (s *Scanner) processARPResults(result *ARPResult) {
	result.mu.Lock()
	defer result.mu.Unlock()

	var hosts []HostEntry
	var conflicts []ConflictEntry

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
		host := HostEntry{
			IP:     ipStr,
			MAC:    strings.ToUpper(mac.String()),
			Vendor: vendor,
			Subnet: subnet,
		}

		// Multiple MACs → check if bond or real conflict
		if len(macs) > 1 {
			devGroups := groupMACsByDevice(macs)
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
				conflicts = append(conflicts, ConflictEntry{
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
	sortIPStrings(ips)
	ipIndex := make(map[string]int)
	for i, ip := range ips {
		ipIndex[ip] = i
	}
	sorted := make([]HostEntry, len(hosts))
	for _, h := range hosts {
		sorted[ipIndex[h.IP]] = h
	}

	s.state.mu.Lock()
	s.state.Hosts = sorted
	s.state.Conflicts = conflicts
	s.state.mu.Unlock()

	// Send alerts for detected conflicts
	if s.alertMgr != nil && len(conflicts) > 0 {
		for _, c := range conflicts {
			go s.alertMgr.SendConflictAlert(c)
		}
	}
}

// processDHCPResults converts DHCPServerInfo to DHCPServerJSON
func (s *Scanner) processDHCPResults(servers []DHCPServerInfo) {
	var result []DHCPServerJSON
	for _, srv := range servers {
		entry := DHCPServerJSON{
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

	s.state.mu.Lock()
	s.state.DHCPServers = result
	s.state.mu.Unlock()
}

// resolveHostnames resolves DNS PTR for all discovered hosts
func (s *Scanner) resolveHostnames() {
	s.state.mu.RLock()
	hostsCopy := make([]HostEntry, len(s.state.Hosts))
	copy(hostsCopy, s.state.Hosts)
	s.state.mu.RUnlock()

	var ips []string
	for _, h := range hostsCopy {
		ips = append(ips, h.IP)
	}

	entries := ResolveHostnames(ips)

	// Build hostname map
	s.hostnameMu.Lock()
	for _, e := range entries {
		s.hostnameMap[e.IP] = e.Hostname
	}
	s.hostnameMu.Unlock()

	// Update hosts and conflicts with hostnames
	s.state.mu.Lock()
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
	s.state.mu.Unlock()
}

// checkDNSSpoofing runs DNS spoofing verification
func (s *Scanner) checkDNSSpoofing() {
	s.state.mu.RLock()
	var dnsServers []string
	for _, srv := range s.state.DHCPServers {
		for _, dns := range srv.DNS {
			dnsServers = append(dnsServers, dns)
		}
	}
	s.state.mu.RUnlock()

	if len(dnsServers) == 0 {
		return
	}

	alerts := CheckDNSSpoofing(dnsServers)
	if len(alerts) > 0 {
		s.state.mu.Lock()
		s.state.DNSAlerts = append(s.state.DNSAlerts, alerts...)
		s.state.mu.Unlock()
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

		go func() {
			defer wg.Done()
			entries, _ := ListenHSRP(s.iface.Name, 30*time.Second, s.bgStopCh)
			if len(entries) > 0 {
				s.state.mu.Lock()
				s.state.HSRPEntries = deduplicateHSRP(append(s.state.HSRPEntries, entries...))
				s.state.mu.Unlock()
			}
		}()

		go func() {
			defer wg.Done()
			entries, _ := ListenVRRP(s.iface.Name, 30*time.Second, s.bgStopCh)
			if len(entries) > 0 {
				s.state.mu.Lock()
				s.state.VRRPEntries = deduplicateVRRP(append(s.state.VRRPEntries, entries...))
				s.state.mu.Unlock()
			}
		}()

		go func() {
			defer wg.Done()
			entries, _ := ListenLLDP(s.iface.Name, 30*time.Second, s.bgStopCh)
			if len(entries) > 0 {
				s.state.mu.Lock()
				s.state.LLDPNeighbors = deduplicateLLDP(append(s.state.LLDPNeighbors, entries...))
				s.state.mu.Unlock()
			}
		}()

		go func() {
			defer wg.Done()
			entries, _ := ListenCDP(s.iface.Name, 30*time.Second, s.bgStopCh)
			if len(entries) > 0 {
				s.state.mu.Lock()
				s.state.CDPNeighbors = deduplicateCDP(append(s.state.CDPNeighbors, entries...))
				s.state.mu.Unlock()
			}
		}()

		wg.Wait()
	}
}

// backgroundARPMonitor continuously monitors ARP traffic for spoofing
func (s *Scanner) backgroundARPMonitor() {
	if s.arpResult == nil {
		return
	}

	// Build baseline IP->MAC mapping (all known IPs, using all observed MACs)
	baseline := make(map[string][]string)
	s.arpResult.mu.Lock()
	for ip, macs := range s.arpResult.Entries {
		for _, m := range macs {
			baseline[ip] = append(baseline[ip], m.String())
		}
	}
	s.arpResult.mu.Unlock()

	// Find gateway IP (routing table first, then DHCP)
	gatewayIP := getDefaultGateway()
	if gatewayIP == "" {
		s.state.mu.RLock()
		for _, srv := range s.state.DHCPServers {
			if srv.Router != "" {
				gatewayIP = srv.Router
				break
			}
		}
		s.state.mu.RUnlock()
	}

	for {
		select {
		case <-s.bgStopCh:
			return
		default:
		}

		alerts, err := MonitorARP(s.iface.Name, baseline, gatewayIP, 5*time.Second, s.bgStopCh)
		if err != nil {
			log.Printf("ARP 모니터 오류: %v", err)
			continue
		}
		if len(alerts) > 0 {
			s.state.mu.Lock()
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
					s.state.ARPAlerts = append(s.state.ARPAlerts, a)
					// Send conflict alert for new MAC change
					if s.alertMgr != nil {
						conflict := ConflictEntry{
							IP:     a.IP,
							MACs:   []string{a.OldMAC, a.NewMAC},
							Subnet: s.findSubnet(net.ParseIP(a.IP)),
						}
						go s.alertMgr.SendConflictAlert(conflict)
					}
				}
			}
			s.state.mu.Unlock()
		}
	}
}

// Deduplication helpers
func deduplicateHSRP(entries []HSRPEntry) []HSRPEntry {
	seen := make(map[string]int)
	for i, e := range entries {
		key := fmt.Sprintf("%d-%d-%s", e.Version, e.Group, e.SourceIP)
		if idx, ok := seen[key]; ok {
			entries[idx] = e // Update with newer entry
		} else {
			seen[key] = i
		}
	}
	var result []HSRPEntry
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

func deduplicateVRRP(entries []VRRPEntry) []VRRPEntry {
	seen := make(map[string]int)
	for i, e := range entries {
		key := fmt.Sprintf("%d-%s", e.RouterID, e.SourceIP)
		if idx, ok := seen[key]; ok {
			entries[idx] = e
		} else {
			seen[key] = i
		}
	}
	var result []VRRPEntry
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

func deduplicateLLDP(entries []LLDPNeighbor) []LLDPNeighbor {
	seen := make(map[string]int)
	for i, e := range entries {
		key := e.ChassisID + "-" + e.PortID
		if idx, ok := seen[key]; ok {
			entries[idx] = e
		} else {
			seen[key] = i
		}
	}
	var result []LLDPNeighbor
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

func deduplicateCDP(entries []CDPNeighbor) []CDPNeighbor {
	seen := make(map[string]int)
	for i, e := range entries {
		key := e.DeviceID + "-" + e.PortID
		if idx, ok := seen[key]; ok {
			entries[idx] = e
		} else {
			seen[key] = i
		}
	}
	var result []CDPNeighbor
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
