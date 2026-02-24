package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/smtp"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// AlertConfig represents a single alert rule
type AlertConfig struct {
	ID       string   `json:"id"`
	Subnets  []string `json:"subnets"`          // monitored subnets (empty = all)
	Events   []string `json:"events,omitempty"` // monitored events (empty = all)
	Type     string   `json:"type"`             // "email"
	SmtpHost string   `json:"smtpHost,omitempty"`
	SmtpPort int      `json:"smtpPort,omitempty"`
	SmtpFrom string   `json:"smtpFrom,omitempty"` // sender address (From)
	SmtpTo   string   `json:"smtpTo,omitempty"`
	SmtpSSL  bool     `json:"smtpSSL,omitempty"`
	SmtpAuth bool     `json:"smtpAuth,omitempty"`
	SmtpUser string   `json:"smtpUser,omitempty"` // auth credentials
	SmtpPass string   `json:"smtpPass,omitempty"`
}

// AlertManager manages alert configurations and dispatches alerts
type AlertManager struct {
	mu       sync.RWMutex
	configs  []AlertConfig
	filePath string
	encKey   [32]byte
}

// alertConfigDir returns ~/.config/net-finder, creating it if needed
func alertConfigDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("홈 디렉토리 확인 실패: %v", err)
	}
	dir := filepath.Join(home, ".config", "net-finder")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("설정 디렉토리 생성 실패: %v", err)
	}
	return dir, nil
}

// deriveKey generates a deterministic AES-256 key from machine-id + fixed salt
func deriveKey() [32]byte {
	machineID, err := os.ReadFile("/etc/machine-id")
	if err != nil {
		// fallback: hostname
		h, _ := os.Hostname()
		machineID = []byte(h)
	}
	return sha256.Sum256(append([]byte("net-finder-alerts:"), machineID...))
}

// NewAlertManager creates a new AlertManager and loads saved configs
func NewAlertManager() *AlertManager {
	dir, err := alertConfigDir()
	if err != nil {
		log.Printf("알림 설정 경로 오류: %v", err)
		dir = "."
	}
	am := &AlertManager{
		filePath: filepath.Join(dir, "alerts.dat"),
		encKey:   deriveKey(),
	}
	am.load()
	return am
}

func (am *AlertManager) encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(am.encKey[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func (am *AlertManager) decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(am.encKey[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, data := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, data, nil)
}

func (am *AlertManager) load() {
	data, err := os.ReadFile(am.filePath)
	if err != nil {
		return // file doesn't exist yet
	}
	plaintext, err := am.decrypt(data)
	if err != nil {
		log.Printf("알림 설정 복호화 실패: %v", err)
		return
	}
	var configs []AlertConfig
	if err := json.Unmarshal(plaintext, &configs); err != nil {
		log.Printf("알림 설정 파싱 실패: %v", err)
		return
	}
	am.configs = configs
	log.Printf("알림 설정 %d건 로드: %s", len(configs), am.filePath)
}

func (am *AlertManager) save() {
	plaintext, err := json.Marshal(am.configs)
	if err != nil {
		log.Printf("알림 설정 직렬화 실패: %v", err)
		return
	}
	ciphertext, err := am.encrypt(plaintext)
	if err != nil {
		log.Printf("알림 설정 암호화 실패: %v", err)
		return
	}
	if err := os.WriteFile(am.filePath, ciphertext, 0600); err != nil {
		log.Printf("알림 설정 파일 저장 실패: %v", err)
	}
}

// GetConfigs returns all alert configurations
func (am *AlertManager) GetConfigs() []AlertConfig {
	am.mu.RLock()
	defer am.mu.RUnlock()
	result := make([]AlertConfig, len(am.configs))
	copy(result, am.configs)
	return result
}

// AddConfig adds a new alert configuration and saves to file
func (am *AlertManager) AddConfig(cfg AlertConfig) {
	am.mu.Lock()
	defer am.mu.Unlock()
	if cfg.ID == "" {
		cfg.ID = fmt.Sprintf("%d", time.Now().UnixNano())
	}
	am.configs = append(am.configs, cfg)
	am.save()
}

// UpdateConfig updates an existing alert configuration by ID and saves to file
func (am *AlertManager) UpdateConfig(cfg AlertConfig) bool {
	am.mu.Lock()
	defer am.mu.Unlock()
	for i, c := range am.configs {
		if c.ID == cfg.ID {
			am.configs[i] = cfg
			am.save()
			return true
		}
	}
	return false
}

// DeleteConfig removes an alert configuration by ID and saves to file
func (am *AlertManager) DeleteConfig(id string) bool {
	am.mu.Lock()
	defer am.mu.Unlock()
	for i, c := range am.configs {
		if c.ID == id {
			am.configs = append(am.configs[:i], am.configs[i+1:]...)
			am.save()
			return true
		}
	}
	return false
}

// SendConflictAlerts groups conflicts by subnet and sends one email per subnet per config
func (am *AlertManager) SendConflictAlerts(conflicts []ConflictEntry) {
	if len(conflicts) == 0 {
		return
	}
	am.mu.RLock()
	configs := make([]AlertConfig, len(am.configs))
	copy(configs, am.configs)
	am.mu.RUnlock()

	if len(configs) == 0 {
		return
	}

	// Group conflicts by subnet
	bySubnet := make(map[string][]ConflictEntry)
	var subnetOrder []string
	for _, c := range conflicts {
		key := c.Subnet
		if key == "" {
			key = "(unknown)"
		}
		if _, ok := bySubnet[key]; !ok {
			subnetOrder = append(subnetOrder, key)
		}
		bySubnet[key] = append(bySubnet[key], c)
	}

	for _, cfg := range configs {
		if !hasEvent(cfg, "conflicts") {
			continue
		}
		for _, subnet := range subnetOrder {
			entries := bySubnet[subnet]
			if !matchesSubnetStr(cfg, subnet) {
				continue
			}
			subject := fmt.Sprintf("[Net Finder] IP Conflict — %s (%d)", subnet, len(entries))
			body := buildHTMLReport(subnet, entries)
			if err := sendEmailHTML(cfg, subject, body); err != nil {
				log.Printf("알림 발송 실패 [%s] %s: %v", cfg.ID, subnet, err)
			}
		}
	}
}

// TestAlert sends test alert emails based on cfg.Events
func (am *AlertManager) TestAlert(cfg AlertConfig) error {
	sent := 0
	var lastErr error

	if hasEvent(cfg, "conflicts") {
		testConflicts := []ConflictEntry{
			{IP: "192.168.1.100", MACs: []string{"AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02"}, Vendors: []string{"Vendor A", "Vendor B"}, Subnet: "192.168.1.0/24"},
			{IP: "192.168.1.200", MACs: []string{"11:22:33:44:55:01", "11:22:33:44:55:02", "11:22:33:44:55:03"}, Vendors: []string{"Vendor C", "Vendor D", "Vendor E"}, Subnet: "192.168.1.0/24"},
		}
		subject := fmt.Sprintf("[Net Finder] IP Conflict — %s (%d)", "192.168.1.0/24", len(testConflicts))
		body := buildHTMLReport("192.168.1.0/24", testConflicts)
		if err := sendEmailHTML(cfg, subject, body); err != nil {
			lastErr = err
		} else {
			sent++
		}
	}

	if hasEvent(cfg, "hosts") {
		testHosts := []HostEntry{
			{IP: "192.168.1.1", Hostname: "gateway.local", MAC: "AA:BB:CC:DD:EE:01", Vendor: "Cisco Systems", Subnet: "192.168.1.0/24"},
			{IP: "192.168.1.10", Hostname: "server.local", MAC: "11:22:33:44:55:66", Vendor: "Dell Inc.", Subnet: "192.168.1.0/24"},
			{IP: "192.168.1.20", MAC: "FF:EE:DD:CC:BB:AA", Vendor: "HP Enterprise", Subnet: "192.168.1.0/24"},
		}
		subject := fmt.Sprintf("[Net Finder] Host Discovery — %s (%d hosts)", "192.168.1.0/24", len(testHosts))
		body := buildHostHTMLReport("192.168.1.0/24", testHosts)
		if err := sendEmailHTML(cfg, subject, body); err != nil {
			lastErr = err
		} else {
			sent++
		}
	}

	if hasEvent(cfg, "dhcp") {
		testDHCP := []DHCPServerJSON{
			{ServerIP: "192.168.1.1", ServerMAC: "AA:BB:CC:DD:EE:01", Vendor: "Cisco Systems", OfferedIP: "192.168.1.100", SubnetMask: "255.255.255.0", Router: "192.168.1.1", DNS: []string{"8.8.8.8", "8.8.4.4"}, LeaseTime: 86400},
		}
		subject := fmt.Sprintf("[Net Finder] DHCP Servers Detected (%d)", len(testDHCP))
		body := buildDHCPHTMLReport(testDHCP)
		if err := sendEmailHTML(cfg, subject, body); err != nil {
			lastErr = err
		} else {
			sent++
		}
	}

	if hasEvent(cfg, "hsrp_vrrp") {
		testHSRP := []HSRPEntry{
			{Version: 2, Group: 1, Priority: 110, State: "Active", VirtualIP: "192.168.1.254", HelloTime: 3, HoldTime: 10, SourceIP: "192.168.1.2", SourceMAC: "00:00:0C:9F:F0:01", Timestamp: time.Now().Format("15:04:05")},
		}
		testVRRP := []VRRPEntry{
			{Version: 3, RouterID: 1, Priority: 100, IPAddresses: []string{"192.168.1.254"}, AdverInt: 1, SourceIP: "192.168.1.3", SourceMAC: "00:00:5E:00:01:01", Timestamp: time.Now().Format("15:04:05")},
		}
		subject := "[Net Finder] HSRP/VRRP Detected"
		body := buildProtocolHTMLReport(testHSRP, testVRRP)
		if err := sendEmailHTML(cfg, subject, body); err != nil {
			lastErr = err
		} else {
			sent++
		}
	}

	if hasEvent(cfg, "lldp_cdp") {
		testLLDP := []LLDPNeighbor{
			{ChassisID: "AA:BB:CC:DD:EE:01", PortID: "Gi0/1", SysName: "switch01.local", SysDesc: "Cisco IOS", MgmtAddr: "192.168.1.2", TTL: 120, SourceMAC: "AA:BB:CC:DD:EE:01", Timestamp: time.Now().Format("15:04:05")},
		}
		testCDP := []CDPNeighbor{
			{DeviceID: "switch02.local", Addresses: []string{"192.168.1.3"}, PortID: "Gi0/2", Platform: "cisco WS-C3750", Version: "15.0(2)SE", NativeVLAN: 1, SourceMAC: "11:22:33:44:55:66", Timestamp: time.Now().Format("15:04:05")},
		}
		subject := "[Net Finder] LLDP/CDP Neighbors Detected"
		body := buildDiscoveryHTMLReport(testLLDP, testCDP)
		if err := sendEmailHTML(cfg, subject, body); err != nil {
			lastErr = err
		} else {
			sent++
		}
	}

	if hasEvent(cfg, "arp_spoofing") || hasEvent(cfg, "dns_spoofing") {
		var arpAlerts []ARPSpoofAlert
		var dnsAlerts []DNSSpoofAlert
		if hasEvent(cfg, "arp_spoofing") {
			arpAlerts = []ARPSpoofAlert{
				{IP: "192.168.1.1", OldMAC: "AA:BB:CC:DD:EE:01", NewMAC: "FF:FF:FF:00:11:22", AlertType: "gateway_mac_change", Severity: "critical", Message: "Gateway 192.168.1.1 MAC changed", Count: 5, FirstSeen: time.Now().Add(-2 * time.Minute).Format("15:04:05"), Timestamp: time.Now().Format("15:04:05"), Subnet: "192.168.1.0/24"},
			}
		}
		if hasEvent(cfg, "dns_spoofing") {
			dnsAlerts = []DNSSpoofAlert{
				{Domain: "example.com", Server1: "8.8.8.8", Response1: "93.184.216.34", Server2: "192.168.1.1", Response2: "10.0.0.99", AlertType: "dns_mismatch", Severity: "critical", Message: "DNS response mismatch for example.com", Timestamp: time.Now().Format("15:04:05")},
			}
		}
		subject := buildSecuritySubject(arpAlerts, dnsAlerts)
		body := buildSecurityHTMLReport(arpAlerts, dnsAlerts)
		if err := sendEmailHTML(cfg, subject, body); err != nil {
			lastErr = err
		} else {
			sent++
		}
	}

	// If no events selected, send default IP Conflict test for backward compatibility
	if sent == 0 && lastErr == nil {
		testConflicts := []ConflictEntry{
			{IP: "192.168.1.100", MACs: []string{"AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02"}, Vendors: []string{"Vendor A", "Vendor B"}, Subnet: "192.168.1.0/24"},
		}
		subject := fmt.Sprintf("[Net Finder] IP Conflict — %s (%d)", "192.168.1.0/24", len(testConflicts))
		body := buildHTMLReport("192.168.1.0/24", testConflicts)
		return sendEmailHTML(cfg, subject, body)
	}
	return lastErr
}

func matchesSubnetStr(cfg AlertConfig, subnet string) bool {
	if len(cfg.Subnets) == 0 {
		return true
	}
	for _, s := range cfg.Subnets {
		if s == subnet {
			return true
		}
	}
	return false
}

func hasEvent(cfg AlertConfig, event string) bool {
	if len(cfg.Events) == 0 {
		return true
	}
	for _, e := range cfg.Events {
		if e == event {
			return true
		}
	}
	return false
}

func buildHTMLReport(subnet string, conflicts []ConflictEntry) string {
	now := time.Now().Format("2006-01-02 15:04:05")

	var b strings.Builder
	b.WriteString(`<!DOCTYPE html><html><head><meta charset="UTF-8"></head><body style="margin:0;padding:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f5f5f5">`)
	b.WriteString(`<div style="max-width:800px;margin:20px auto;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.1)">`)

	// Header
	b.WriteString(`<div style="background:#d32f2f;color:#fff;padding:20px 24px">`)
	b.WriteString(`<h2 style="margin:0 0 4px;font-size:18px">IP Conflict Detected</h2>`)
	b.WriteString(fmt.Sprintf(`<div style="font-size:13px;opacity:0.9">Subnet: <strong>%s</strong> &nbsp;|&nbsp; %d conflict(s) &nbsp;|&nbsp; %s</div>`,
		htmlEsc(subnet), len(conflicts), htmlEsc(now)))
	b.WriteString(`</div>`)

	// Table
	b.WriteString(`<div style="padding:16px 24px">`)
	b.WriteString(`<table style="width:100%;border-collapse:collapse;font-size:14px">`)
	b.WriteString(`<thead><tr style="background:#f5f5f5">`)
	b.WriteString(`<th style="padding:12px 16px;text-align:left;border-bottom:2px solid #d32f2f;font-weight:600;white-space:nowrap">IP</th>`)
	b.WriteString(`<th style="padding:12px 16px;text-align:left;border-bottom:2px solid #d32f2f;font-weight:600;white-space:nowrap">Hostname</th>`)
	b.WriteString(`<th style="padding:12px 16px;text-align:left;border-bottom:2px solid #d32f2f;font-weight:600;white-space:nowrap">MAC Address</th>`)
	b.WriteString(`<th style="padding:12px 16px;text-align:left;border-bottom:2px solid #d32f2f;font-weight:600;white-space:nowrap">Vendor</th>`)
	b.WriteString(`</tr></thead><tbody>`)

	for _, c := range conflicts {
		hostname := c.Hostname
		if hostname == "" {
			hostname = "-"
		}
		macHTML := strings.Join(macsToHTML(c.MACs), "<br>")
		vendorHTML := strings.Join(vendorsToHTML(c.Vendors), "<br>")

		b.WriteString(`<tr style="border-bottom:1px solid #eee">`)
		b.WriteString(fmt.Sprintf(`<td style="padding:14px 16px;font-weight:600;white-space:nowrap">%s</td>`, htmlEsc(c.IP)))
		b.WriteString(fmt.Sprintf(`<td style="padding:14px 16px;color:#666">%s</td>`, htmlEsc(hostname)))
		b.WriteString(fmt.Sprintf(`<td style="padding:14px 16px;font-family:'Courier New',monospace;font-size:13px;white-space:nowrap">%s</td>`, macHTML))
		b.WriteString(fmt.Sprintf(`<td style="padding:14px 16px">%s</td>`, vendorHTML))
		b.WriteString(`</tr>`)
	}

	b.WriteString(`</tbody></table></div>`)

	// Footer
	b.WriteString(`<div style="padding:12px 24px;background:#f5f5f5;font-size:12px;color:#999;text-align:center">`)
	b.WriteString(`Sent by <strong>Net Finder</strong></div>`)
	b.WriteString(`</div></body></html>`)

	return b.String()
}

func htmlEsc(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, `"`, "&quot;")
	return s
}

func macsToHTML(macs []string) []string {
	out := make([]string, len(macs))
	for i, m := range macs {
		out[i] = htmlEsc(m)
	}
	return out
}

func vendorsToHTML(vendors []string) []string {
	out := make([]string, len(vendors))
	for i, v := range vendors {
		out[i] = htmlEsc(v)
	}
	return out
}

func sendEmailHTML(cfg AlertConfig, subject, htmlBody string) error {
	if cfg.SmtpHost == "" || cfg.SmtpTo == "" {
		return fmt.Errorf("SMTP host and recipient required")
	}
	port := cfg.SmtpPort
	if port == 0 {
		if cfg.SmtpSSL {
			port = 465
		} else {
			port = 25
		}
	}
	addr := fmt.Sprintf("%s:%d", cfg.SmtpHost, port)

	from := cfg.SmtpFrom
	if from == "" {
		from = "netfinder@localhost"
	}

	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n%s",
		from, cfg.SmtpTo, subject, htmlBody)

	if cfg.SmtpSSL {
		return sendEmailSSL(cfg, addr, from, msg)
	}
	return sendEmailStartTLS(cfg, addr, from, msg)
}

// sendEmailSSL connects via implicit TLS (port 465)
func sendEmailSSL(cfg AlertConfig, addr, from, msg string) error {
	tlsCfg := &tls.Config{ServerName: cfg.SmtpHost}
	conn, err := tls.Dial("tcp", addr, tlsCfg)
	if err != nil {
		return fmt.Errorf("TLS dial failed: %v", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, cfg.SmtpHost)
	if err != nil {
		return fmt.Errorf("SMTP client failed: %v", err)
	}
	defer client.Close()

	if cfg.SmtpAuth && cfg.SmtpUser != "" && cfg.SmtpPass != "" {
		auth := smtp.PlainAuth("", cfg.SmtpUser, cfg.SmtpPass, cfg.SmtpHost)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("SMTP auth failed: %v", err)
		}
	}

	if err := client.Mail(from); err != nil {
		return err
	}
	if err := client.Rcpt(cfg.SmtpTo); err != nil {
		return err
	}
	w, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write([]byte(msg)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return client.Quit()
}

// SendSecurityAlerts sends a security alert email for ARP/DNS spoofing events
func (am *AlertManager) SendSecurityAlerts(arpAlerts []ARPSpoofAlert, dnsAlerts []DNSSpoofAlert) {
	if len(arpAlerts) == 0 && len(dnsAlerts) == 0 {
		return
	}
	am.mu.RLock()
	configs := make([]AlertConfig, len(am.configs))
	copy(configs, am.configs)
	am.mu.RUnlock()

	if len(configs) == 0 {
		return
	}

	for _, cfg := range configs {
		// Filter ARP alerts by subnet and event
		var filteredARP []ARPSpoofAlert
		if hasEvent(cfg, "arp_spoofing") {
			for _, a := range arpAlerts {
				subnet := a.Subnet
				if subnet == "" {
					subnet = "(unknown)"
				}
				if matchesSubnetStr(cfg, subnet) {
					filteredARP = append(filteredARP, a)
				}
			}
		}

		// Filter DNS alerts by event
		var filteredDNS []DNSSpoofAlert
		if hasEvent(cfg, "dns_spoofing") {
			filteredDNS = dnsAlerts
		}

		if len(filteredARP) == 0 && len(filteredDNS) == 0 {
			continue
		}

		subject := buildSecuritySubject(filteredARP, filteredDNS)
		body := buildSecurityHTMLReport(filteredARP, filteredDNS)
		if err := sendEmailHTML(cfg, subject, body); err != nil {
			log.Printf("보안 알림 발송 실패 [%s]: %v", cfg.ID, err)
		}
	}
}

// SendHostAlerts sends host discovery alerts grouped by subnet
func (am *AlertManager) SendHostAlerts(hosts []HostEntry) {
	if len(hosts) == 0 {
		return
	}
	am.mu.RLock()
	configs := make([]AlertConfig, len(am.configs))
	copy(configs, am.configs)
	am.mu.RUnlock()

	if len(configs) == 0 {
		return
	}

	bySubnet := make(map[string][]HostEntry)
	var subnetOrder []string
	for _, h := range hosts {
		key := h.Subnet
		if key == "" {
			key = "(unknown)"
		}
		if _, ok := bySubnet[key]; !ok {
			subnetOrder = append(subnetOrder, key)
		}
		bySubnet[key] = append(bySubnet[key], h)
	}

	for _, cfg := range configs {
		if !hasEvent(cfg, "hosts") {
			continue
		}
		for _, subnet := range subnetOrder {
			entries := bySubnet[subnet]
			if !matchesSubnetStr(cfg, subnet) {
				continue
			}
			subject := fmt.Sprintf("[Net Finder] Host Discovery — %s (%d hosts)", subnet, len(entries))
			body := buildHostHTMLReport(subnet, entries)
			if err := sendEmailHTML(cfg, subject, body); err != nil {
				log.Printf("호스트 알림 발송 실패 [%s] %s: %v", cfg.ID, subnet, err)
			}
		}
	}
}

// SendDHCPAlerts sends DHCP server detection alerts
func (am *AlertManager) SendDHCPAlerts(servers []DHCPServerJSON) {
	if len(servers) == 0 {
		return
	}
	am.mu.RLock()
	configs := make([]AlertConfig, len(am.configs))
	copy(configs, am.configs)
	am.mu.RUnlock()

	if len(configs) == 0 {
		return
	}

	for _, cfg := range configs {
		if !hasEvent(cfg, "dhcp") {
			continue
		}
		subject := fmt.Sprintf("[Net Finder] DHCP Servers Detected (%d)", len(servers))
		body := buildDHCPHTMLReport(servers)
		if err := sendEmailHTML(cfg, subject, body); err != nil {
			log.Printf("DHCP 알림 발송 실패 [%s]: %v", cfg.ID, err)
		}
	}
}

// SendProtocolAlerts sends HSRP/VRRP detection alerts
func (am *AlertManager) SendProtocolAlerts(hsrp []HSRPEntry, vrrp []VRRPEntry) {
	if len(hsrp) == 0 && len(vrrp) == 0 {
		return
	}
	am.mu.RLock()
	configs := make([]AlertConfig, len(am.configs))
	copy(configs, am.configs)
	am.mu.RUnlock()

	if len(configs) == 0 {
		return
	}

	for _, cfg := range configs {
		if !hasEvent(cfg, "hsrp_vrrp") {
			continue
		}
		var parts []string
		if len(hsrp) > 0 {
			parts = append(parts, fmt.Sprintf("HSRP(%d)", len(hsrp)))
		}
		if len(vrrp) > 0 {
			parts = append(parts, fmt.Sprintf("VRRP(%d)", len(vrrp)))
		}
		subject := fmt.Sprintf("[Net Finder] %s Detected", strings.Join(parts, " / "))
		body := buildProtocolHTMLReport(hsrp, vrrp)
		if err := sendEmailHTML(cfg, subject, body); err != nil {
			log.Printf("프로토콜 알림 발송 실패 [%s]: %v", cfg.ID, err)
		}
	}
}

// SendDiscoveryAlerts sends LLDP/CDP neighbor detection alerts
func (am *AlertManager) SendDiscoveryAlerts(lldp []LLDPNeighbor, cdp []CDPNeighbor) {
	if len(lldp) == 0 && len(cdp) == 0 {
		return
	}
	am.mu.RLock()
	configs := make([]AlertConfig, len(am.configs))
	copy(configs, am.configs)
	am.mu.RUnlock()

	if len(configs) == 0 {
		return
	}

	for _, cfg := range configs {
		if !hasEvent(cfg, "lldp_cdp") {
			continue
		}
		var parts []string
		if len(lldp) > 0 {
			parts = append(parts, fmt.Sprintf("LLDP(%d)", len(lldp)))
		}
		if len(cdp) > 0 {
			parts = append(parts, fmt.Sprintf("CDP(%d)", len(cdp)))
		}
		subject := fmt.Sprintf("[Net Finder] %s Neighbors Detected", strings.Join(parts, " / "))
		body := buildDiscoveryHTMLReport(lldp, cdp)
		if err := sendEmailHTML(cfg, subject, body); err != nil {
			log.Printf("디스커버리 알림 발송 실패 [%s]: %v", cfg.ID, err)
		}
	}
}

func buildSecuritySubject(arpAlerts []ARPSpoofAlert, dnsAlerts []DNSSpoofAlert) string {
	var parts []string
	if len(arpAlerts) > 0 {
		parts = append(parts, fmt.Sprintf("ARP Spoofing (%d)", len(arpAlerts)))
	}
	if len(dnsAlerts) > 0 {
		parts = append(parts, fmt.Sprintf("DNS Spoofing (%d)", len(dnsAlerts)))
	}
	return fmt.Sprintf("[Net Finder] Security Alert — %s", strings.Join(parts, ", "))
}

func buildSecurityHTMLReport(arpAlerts []ARPSpoofAlert, dnsAlerts []DNSSpoofAlert) string {
	now := time.Now().Format("2006-01-02 15:04:05")
	total := len(arpAlerts) + len(dnsAlerts)

	var b strings.Builder
	b.WriteString(`<!DOCTYPE html><html><head><meta charset="UTF-8"></head><body style="margin:0;padding:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f5f5f5">`)
	b.WriteString(`<div style="max-width:800px;margin:20px auto;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.1)">`)

	// Header (deep orange)
	b.WriteString(`<div style="background:#e65100;color:#fff;padding:20px 24px">`)
	b.WriteString(`<h2 style="margin:0 0 4px;font-size:18px">Security Alert</h2>`)
	b.WriteString(fmt.Sprintf(`<div style="font-size:13px;opacity:0.9">%d alert(s) &nbsp;|&nbsp; %s</div>`,
		total, htmlEsc(now)))
	b.WriteString(`</div>`)

	// ARP Spoofing section
	if len(arpAlerts) > 0 {
		b.WriteString(`<div style="padding:16px 24px">`)
		b.WriteString(fmt.Sprintf(`<h3 style="margin:0 0 12px;font-size:15px;color:#e65100">ARP Spoofing (%d)</h3>`, len(arpAlerts)))
		b.WriteString(`<table style="width:100%;border-collapse:collapse;font-size:14px">`)
		b.WriteString(`<thead><tr style="background:#f5f5f5">`)
		b.WriteString(`<th style="padding:12px 16px;text-align:left;border-bottom:2px solid #e65100;font-weight:600;white-space:nowrap">Severity</th>`)
		b.WriteString(`<th style="padding:12px 16px;text-align:left;border-bottom:2px solid #e65100;font-weight:600;white-space:nowrap">Target IP</th>`)
		b.WriteString(`<th style="padding:12px 16px;text-align:left;border-bottom:2px solid #e65100;font-weight:600;white-space:nowrap">Known MAC</th>`)
		b.WriteString(`<th style="padding:12px 16px;text-align:left;border-bottom:2px solid #e65100;font-weight:600;white-space:nowrap">Attacker MAC</th>`)
		b.WriteString(`<th style="padding:12px 16px;text-align:left;border-bottom:2px solid #e65100;font-weight:600;white-space:nowrap">Packets</th>`)
		b.WriteString(`<th style="padding:12px 16px;text-align:left;border-bottom:2px solid #e65100;font-weight:600;white-space:nowrap">First Seen</th>`)
		b.WriteString(`<th style="padding:12px 16px;text-align:left;border-bottom:2px solid #e65100;font-weight:600;white-space:nowrap">Last Seen</th>`)
		b.WriteString(`</tr></thead><tbody>`)

		for _, a := range arpAlerts {
			sevColor := "#f57f17"
			if a.Severity == "critical" {
				sevColor = "#d32f2f"
			}
			firstSeen := a.FirstSeen
			if firstSeen == "" {
				firstSeen = a.Timestamp
			}
			b.WriteString(`<tr style="border-bottom:1px solid #eee">`)
			b.WriteString(fmt.Sprintf(`<td style="padding:14px 16px;font-weight:600;color:%s;white-space:nowrap">%s</td>`, sevColor, htmlEsc(strings.ToUpper(a.Severity))))
			b.WriteString(fmt.Sprintf(`<td style="padding:14px 16px;font-weight:600;white-space:nowrap">%s</td>`, htmlEsc(a.IP)))
			b.WriteString(fmt.Sprintf(`<td style="padding:14px 16px;font-family:'Courier New',monospace;font-size:13px;white-space:nowrap">%s</td>`, htmlEsc(a.OldMAC)))
			b.WriteString(fmt.Sprintf(`<td style="padding:14px 16px;font-family:'Courier New',monospace;font-size:13px;white-space:nowrap">%s</td>`, htmlEsc(a.NewMAC)))
			b.WriteString(fmt.Sprintf(`<td style="padding:14px 16px;text-align:center;font-weight:600">%d</td>`, a.Count))
			b.WriteString(fmt.Sprintf(`<td style="padding:14px 16px;white-space:nowrap">%s</td>`, htmlEsc(firstSeen)))
			b.WriteString(fmt.Sprintf(`<td style="padding:14px 16px;white-space:nowrap">%s</td>`, htmlEsc(a.Timestamp)))
			b.WriteString(`</tr>`)
		}

		b.WriteString(`</tbody></table></div>`)
	}

	// DNS Spoofing section
	if len(dnsAlerts) > 0 {
		b.WriteString(`<div style="padding:16px 24px">`)
		b.WriteString(fmt.Sprintf(`<h3 style="margin:0 0 12px;font-size:15px;color:#e65100">DNS Spoofing (%d)</h3>`, len(dnsAlerts)))
		b.WriteString(`<table style="width:100%;border-collapse:collapse;font-size:14px">`)
		b.WriteString(`<thead><tr style="background:#f5f5f5">`)
		b.WriteString(`<th style="padding:12px 16px;text-align:left;border-bottom:2px solid #e65100;font-weight:600;white-space:nowrap">Severity</th>`)
		b.WriteString(`<th style="padding:12px 16px;text-align:left;border-bottom:2px solid #e65100;font-weight:600;white-space:nowrap">Type</th>`)
		b.WriteString(`<th style="padding:12px 16px;text-align:left;border-bottom:2px solid #e65100;font-weight:600;white-space:nowrap">Domain</th>`)
		b.WriteString(`<th style="padding:12px 16px;text-align:left;border-bottom:2px solid #e65100;font-weight:600;white-space:nowrap">Message</th>`)
		b.WriteString(`<th style="padding:12px 16px;text-align:left;border-bottom:2px solid #e65100;font-weight:600;white-space:nowrap">Time</th>`)
		b.WriteString(`</tr></thead><tbody>`)

		for _, a := range dnsAlerts {
			sevColor := "#f57f17"
			if a.Severity == "critical" {
				sevColor = "#d32f2f"
			}
			b.WriteString(`<tr style="border-bottom:1px solid #eee">`)
			b.WriteString(fmt.Sprintf(`<td style="padding:14px 16px;font-weight:600;color:%s;white-space:nowrap">%s</td>`, sevColor, htmlEsc(strings.ToUpper(a.Severity))))
			b.WriteString(fmt.Sprintf(`<td style="padding:14px 16px;white-space:nowrap">%s</td>`, htmlEsc(a.AlertType)))
			b.WriteString(fmt.Sprintf(`<td style="padding:14px 16px;font-weight:600">%s</td>`, htmlEsc(a.Domain)))
			b.WriteString(fmt.Sprintf(`<td style="padding:14px 16px">%s</td>`, htmlEsc(a.Message)))
			b.WriteString(fmt.Sprintf(`<td style="padding:14px 16px;white-space:nowrap">%s</td>`, htmlEsc(a.Timestamp)))
			b.WriteString(`</tr>`)
		}

		b.WriteString(`</tbody></table></div>`)
	}

	// Footer
	b.WriteString(`<div style="padding:12px 24px;background:#f5f5f5;font-size:12px;color:#999;text-align:center">`)
	b.WriteString(`Sent by <strong>Net Finder</strong></div>`)
	b.WriteString(`</div></body></html>`)

	return b.String()
}

func buildHostHTMLReport(subnet string, hosts []HostEntry) string {
	now := time.Now().Format("2006-01-02 15:04:05")

	var b strings.Builder
	b.WriteString(`<!DOCTYPE html><html><head><meta charset="UTF-8"></head><body style="margin:0;padding:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f5f5f5">`)
	b.WriteString(`<div style="max-width:800px;margin:20px auto;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.1)">`)

	b.WriteString(`<div style="background:#1976d2;color:#fff;padding:20px 24px">`)
	b.WriteString(`<h2 style="margin:0 0 4px;font-size:18px">Host Discovery</h2>`)
	b.WriteString(fmt.Sprintf(`<div style="font-size:13px;opacity:0.9">Subnet: <strong>%s</strong> &nbsp;|&nbsp; %d host(s) &nbsp;|&nbsp; %s</div>`,
		htmlEsc(subnet), len(hosts), htmlEsc(now)))
	b.WriteString(`</div>`)

	b.WriteString(`<div style="padding:16px 24px">`)
	b.WriteString(`<table style="width:100%;border-collapse:collapse;font-size:14px">`)
	b.WriteString(`<thead><tr style="background:#f5f5f5">`)
	b.WriteString(`<th style="padding:12px 16px;text-align:left;border-bottom:2px solid #1976d2;font-weight:600;white-space:nowrap">IP</th>`)
	b.WriteString(`<th style="padding:12px 16px;text-align:left;border-bottom:2px solid #1976d2;font-weight:600;white-space:nowrap">Hostname</th>`)
	b.WriteString(`<th style="padding:12px 16px;text-align:left;border-bottom:2px solid #1976d2;font-weight:600;white-space:nowrap">MAC Address</th>`)
	b.WriteString(`<th style="padding:12px 16px;text-align:left;border-bottom:2px solid #1976d2;font-weight:600;white-space:nowrap">Vendor</th>`)
	b.WriteString(`</tr></thead><tbody>`)

	for _, h := range hosts {
		hostname := h.Hostname
		if hostname == "" {
			hostname = "-"
		}
		b.WriteString(`<tr style="border-bottom:1px solid #eee">`)
		b.WriteString(fmt.Sprintf(`<td style="padding:14px 16px;font-weight:600;white-space:nowrap">%s</td>`, htmlEsc(h.IP)))
		b.WriteString(fmt.Sprintf(`<td style="padding:14px 16px;color:#666">%s</td>`, htmlEsc(hostname)))
		b.WriteString(fmt.Sprintf(`<td style="padding:14px 16px;font-family:'Courier New',monospace;font-size:13px;white-space:nowrap">%s</td>`, htmlEsc(h.MAC)))
		b.WriteString(fmt.Sprintf(`<td style="padding:14px 16px">%s</td>`, htmlEsc(h.Vendor)))
		b.WriteString(`</tr>`)
	}

	b.WriteString(`</tbody></table></div>`)
	b.WriteString(`<div style="padding:12px 24px;background:#f5f5f5;font-size:12px;color:#999;text-align:center">`)
	b.WriteString(`Sent by <strong>Net Finder</strong></div>`)
	b.WriteString(`</div></body></html>`)
	return b.String()
}

func buildDHCPHTMLReport(servers []DHCPServerJSON) string {
	now := time.Now().Format("2006-01-02 15:04:05")

	var b strings.Builder
	b.WriteString(`<!DOCTYPE html><html><head><meta charset="UTF-8"></head><body style="margin:0;padding:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f5f5f5">`)
	b.WriteString(`<div style="max-width:800px;margin:20px auto;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.1)">`)

	b.WriteString(`<div style="background:#388e3c;color:#fff;padding:20px 24px">`)
	b.WriteString(`<h2 style="margin:0 0 4px;font-size:18px">DHCP Servers Detected</h2>`)
	b.WriteString(fmt.Sprintf(`<div style="font-size:13px;opacity:0.9">%d server(s) &nbsp;|&nbsp; %s</div>`,
		len(servers), htmlEsc(now)))
	b.WriteString(`</div>`)

	b.WriteString(`<div style="padding:16px 24px">`)
	b.WriteString(`<table style="width:100%;border-collapse:collapse;font-size:14px">`)
	b.WriteString(`<thead><tr style="background:#f5f5f5">`)
	b.WriteString(`<th style="padding:12px 16px;text-align:left;border-bottom:2px solid #388e3c;font-weight:600;white-space:nowrap">Server IP</th>`)
	b.WriteString(`<th style="padding:12px 16px;text-align:left;border-bottom:2px solid #388e3c;font-weight:600;white-space:nowrap">Server MAC</th>`)
	b.WriteString(`<th style="padding:12px 16px;text-align:left;border-bottom:2px solid #388e3c;font-weight:600;white-space:nowrap">Vendor</th>`)
	b.WriteString(`<th style="padding:12px 16px;text-align:left;border-bottom:2px solid #388e3c;font-weight:600;white-space:nowrap">Offered IP</th>`)
	b.WriteString(`<th style="padding:12px 16px;text-align:left;border-bottom:2px solid #388e3c;font-weight:600;white-space:nowrap">Gateway</th>`)
	b.WriteString(`<th style="padding:12px 16px;text-align:left;border-bottom:2px solid #388e3c;font-weight:600;white-space:nowrap">DNS</th>`)
	b.WriteString(`</tr></thead><tbody>`)

	for _, s := range servers {
		dns := strings.Join(s.DNS, ", ")
		b.WriteString(`<tr style="border-bottom:1px solid #eee">`)
		b.WriteString(fmt.Sprintf(`<td style="padding:14px 16px;font-weight:600;white-space:nowrap">%s</td>`, htmlEsc(s.ServerIP)))
		b.WriteString(fmt.Sprintf(`<td style="padding:14px 16px;font-family:'Courier New',monospace;font-size:13px;white-space:nowrap">%s</td>`, htmlEsc(s.ServerMAC)))
		b.WriteString(fmt.Sprintf(`<td style="padding:14px 16px">%s</td>`, htmlEsc(s.Vendor)))
		b.WriteString(fmt.Sprintf(`<td style="padding:14px 16px;white-space:nowrap">%s</td>`, htmlEsc(s.OfferedIP)))
		b.WriteString(fmt.Sprintf(`<td style="padding:14px 16px;white-space:nowrap">%s</td>`, htmlEsc(s.Router)))
		b.WriteString(fmt.Sprintf(`<td style="padding:14px 16px">%s</td>`, htmlEsc(dns)))
		b.WriteString(`</tr>`)
	}

	b.WriteString(`</tbody></table></div>`)
	b.WriteString(`<div style="padding:12px 24px;background:#f5f5f5;font-size:12px;color:#999;text-align:center">`)
	b.WriteString(`Sent by <strong>Net Finder</strong></div>`)
	b.WriteString(`</div></body></html>`)
	return b.String()
}

func buildProtocolHTMLReport(hsrp []HSRPEntry, vrrp []VRRPEntry) string {
	now := time.Now().Format("2006-01-02 15:04:05")
	total := len(hsrp) + len(vrrp)

	var b strings.Builder
	b.WriteString(`<!DOCTYPE html><html><head><meta charset="UTF-8"></head><body style="margin:0;padding:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f5f5f5">`)
	b.WriteString(`<div style="max-width:800px;margin:20px auto;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.1)">`)

	b.WriteString(`<div style="background:#7b1fa2;color:#fff;padding:20px 24px">`)
	b.WriteString(`<h2 style="margin:0 0 4px;font-size:18px">HSRP/VRRP Detected</h2>`)
	b.WriteString(fmt.Sprintf(`<div style="font-size:13px;opacity:0.9">%d entry(ies) &nbsp;|&nbsp; %s</div>`,
		total, htmlEsc(now)))
	b.WriteString(`</div>`)

	if len(hsrp) > 0 {
		b.WriteString(`<div style="padding:16px 24px">`)
		b.WriteString(fmt.Sprintf(`<h3 style="margin:0 0 12px;font-size:15px;color:#7b1fa2">HSRP (%d)</h3>`, len(hsrp)))
		b.WriteString(`<table style="width:100%;border-collapse:collapse;font-size:14px">`)
		b.WriteString(`<thead><tr style="background:#f5f5f5">`)
		b.WriteString(`<th style="padding:12px 16px;text-align:left;border-bottom:2px solid #7b1fa2;font-weight:600;white-space:nowrap">Version</th>`)
		b.WriteString(`<th style="padding:12px 16px;text-align:left;border-bottom:2px solid #7b1fa2;font-weight:600;white-space:nowrap">Group</th>`)
		b.WriteString(`<th style="padding:12px 16px;text-align:left;border-bottom:2px solid #7b1fa2;font-weight:600;white-space:nowrap">State</th>`)
		b.WriteString(`<th style="padding:12px 16px;text-align:left;border-bottom:2px solid #7b1fa2;font-weight:600;white-space:nowrap">Priority</th>`)
		b.WriteString(`<th style="padding:12px 16px;text-align:left;border-bottom:2px solid #7b1fa2;font-weight:600;white-space:nowrap">Virtual IP</th>`)
		b.WriteString(`<th style="padding:12px 16px;text-align:left;border-bottom:2px solid #7b1fa2;font-weight:600;white-space:nowrap">Source IP</th>`)
		b.WriteString(`<th style="padding:12px 16px;text-align:left;border-bottom:2px solid #7b1fa2;font-weight:600;white-space:nowrap">Time</th>`)
		b.WriteString(`</tr></thead><tbody>`)

		for _, e := range hsrp {
			b.WriteString(`<tr style="border-bottom:1px solid #eee">`)
			b.WriteString(fmt.Sprintf(`<td style="padding:14px 16px">v%d</td>`, e.Version))
			b.WriteString(fmt.Sprintf(`<td style="padding:14px 16px">%d</td>`, e.Group))
			b.WriteString(fmt.Sprintf(`<td style="padding:14px 16px">%s</td>`, htmlEsc(e.State)))
			b.WriteString(fmt.Sprintf(`<td style="padding:14px 16px">%d</td>`, e.Priority))
			b.WriteString(fmt.Sprintf(`<td style="padding:14px 16px;font-weight:600;white-space:nowrap">%s</td>`, htmlEsc(e.VirtualIP)))
			b.WriteString(fmt.Sprintf(`<td style="padding:14px 16px;white-space:nowrap">%s</td>`, htmlEsc(e.SourceIP)))
			b.WriteString(fmt.Sprintf(`<td style="padding:14px 16px;white-space:nowrap">%s</td>`, htmlEsc(e.Timestamp)))
			b.WriteString(`</tr>`)
		}
		b.WriteString(`</tbody></table></div>`)
	}

	if len(vrrp) > 0 {
		b.WriteString(`<div style="padding:16px 24px">`)
		b.WriteString(fmt.Sprintf(`<h3 style="margin:0 0 12px;font-size:15px;color:#7b1fa2">VRRP (%d)</h3>`, len(vrrp)))
		b.WriteString(`<table style="width:100%;border-collapse:collapse;font-size:14px">`)
		b.WriteString(`<thead><tr style="background:#f5f5f5">`)
		b.WriteString(`<th style="padding:12px 16px;text-align:left;border-bottom:2px solid #7b1fa2;font-weight:600;white-space:nowrap">Version</th>`)
		b.WriteString(`<th style="padding:12px 16px;text-align:left;border-bottom:2px solid #7b1fa2;font-weight:600;white-space:nowrap">Router ID</th>`)
		b.WriteString(`<th style="padding:12px 16px;text-align:left;border-bottom:2px solid #7b1fa2;font-weight:600;white-space:nowrap">Priority</th>`)
		b.WriteString(`<th style="padding:12px 16px;text-align:left;border-bottom:2px solid #7b1fa2;font-weight:600;white-space:nowrap">Virtual IP</th>`)
		b.WriteString(`<th style="padding:12px 16px;text-align:left;border-bottom:2px solid #7b1fa2;font-weight:600;white-space:nowrap">Source IP</th>`)
		b.WriteString(`<th style="padding:12px 16px;text-align:left;border-bottom:2px solid #7b1fa2;font-weight:600;white-space:nowrap">Adver Int</th>`)
		b.WriteString(`<th style="padding:12px 16px;text-align:left;border-bottom:2px solid #7b1fa2;font-weight:600;white-space:nowrap">Time</th>`)
		b.WriteString(`</tr></thead><tbody>`)

		for _, e := range vrrp {
			ips := strings.Join(e.IPAddresses, ", ")
			b.WriteString(`<tr style="border-bottom:1px solid #eee">`)
			b.WriteString(fmt.Sprintf(`<td style="padding:14px 16px">v%d</td>`, e.Version))
			b.WriteString(fmt.Sprintf(`<td style="padding:14px 16px">%d</td>`, e.RouterID))
			b.WriteString(fmt.Sprintf(`<td style="padding:14px 16px">%d</td>`, e.Priority))
			b.WriteString(fmt.Sprintf(`<td style="padding:14px 16px;font-weight:600;white-space:nowrap">%s</td>`, htmlEsc(ips)))
			b.WriteString(fmt.Sprintf(`<td style="padding:14px 16px;white-space:nowrap">%s</td>`, htmlEsc(e.SourceIP)))
			b.WriteString(fmt.Sprintf(`<td style="padding:14px 16px">%ds</td>`, e.AdverInt))
			b.WriteString(fmt.Sprintf(`<td style="padding:14px 16px;white-space:nowrap">%s</td>`, htmlEsc(e.Timestamp)))
			b.WriteString(`</tr>`)
		}
		b.WriteString(`</tbody></table></div>`)
	}

	b.WriteString(`<div style="padding:12px 24px;background:#f5f5f5;font-size:12px;color:#999;text-align:center">`)
	b.WriteString(`Sent by <strong>Net Finder</strong></div>`)
	b.WriteString(`</div></body></html>`)
	return b.String()
}

func buildDiscoveryHTMLReport(lldp []LLDPNeighbor, cdp []CDPNeighbor) string {
	now := time.Now().Format("2006-01-02 15:04:05")
	total := len(lldp) + len(cdp)

	var b strings.Builder
	b.WriteString(`<!DOCTYPE html><html><head><meta charset="UTF-8"></head><body style="margin:0;padding:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f5f5f5">`)
	b.WriteString(`<div style="max-width:800px;margin:20px auto;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.1)">`)

	b.WriteString(`<div style="background:#0097a7;color:#fff;padding:20px 24px">`)
	b.WriteString(`<h2 style="margin:0 0 4px;font-size:18px">LLDP/CDP Neighbors Detected</h2>`)
	b.WriteString(fmt.Sprintf(`<div style="font-size:13px;opacity:0.9">%d neighbor(s) &nbsp;|&nbsp; %s</div>`,
		total, htmlEsc(now)))
	b.WriteString(`</div>`)

	if len(lldp) > 0 {
		b.WriteString(`<div style="padding:16px 24px">`)
		b.WriteString(fmt.Sprintf(`<h3 style="margin:0 0 12px;font-size:15px;color:#0097a7">LLDP (%d)</h3>`, len(lldp)))
		b.WriteString(`<table style="width:100%;border-collapse:collapse;font-size:14px">`)
		b.WriteString(`<thead><tr style="background:#f5f5f5">`)
		b.WriteString(`<th style="padding:12px 16px;text-align:left;border-bottom:2px solid #0097a7;font-weight:600;white-space:nowrap">Chassis ID</th>`)
		b.WriteString(`<th style="padding:12px 16px;text-align:left;border-bottom:2px solid #0097a7;font-weight:600;white-space:nowrap">Port ID</th>`)
		b.WriteString(`<th style="padding:12px 16px;text-align:left;border-bottom:2px solid #0097a7;font-weight:600;white-space:nowrap">System Name</th>`)
		b.WriteString(`<th style="padding:12px 16px;text-align:left;border-bottom:2px solid #0097a7;font-weight:600;white-space:nowrap">Mgmt Address</th>`)
		b.WriteString(`<th style="padding:12px 16px;text-align:left;border-bottom:2px solid #0097a7;font-weight:600;white-space:nowrap">Time</th>`)
		b.WriteString(`</tr></thead><tbody>`)

		for _, e := range lldp {
			b.WriteString(`<tr style="border-bottom:1px solid #eee">`)
			b.WriteString(fmt.Sprintf(`<td style="padding:14px 16px;font-family:'Courier New',monospace;font-size:13px;white-space:nowrap">%s</td>`, htmlEsc(e.ChassisID)))
			b.WriteString(fmt.Sprintf(`<td style="padding:14px 16px;white-space:nowrap">%s</td>`, htmlEsc(e.PortID)))
			b.WriteString(fmt.Sprintf(`<td style="padding:14px 16px;font-weight:600;white-space:nowrap">%s</td>`, htmlEsc(e.SysName)))
			b.WriteString(fmt.Sprintf(`<td style="padding:14px 16px;white-space:nowrap">%s</td>`, htmlEsc(e.MgmtAddr)))
			b.WriteString(fmt.Sprintf(`<td style="padding:14px 16px;white-space:nowrap">%s</td>`, htmlEsc(e.Timestamp)))
			b.WriteString(`</tr>`)
		}
		b.WriteString(`</tbody></table></div>`)
	}

	if len(cdp) > 0 {
		b.WriteString(`<div style="padding:16px 24px">`)
		b.WriteString(fmt.Sprintf(`<h3 style="margin:0 0 12px;font-size:15px;color:#0097a7">CDP (%d)</h3>`, len(cdp)))
		b.WriteString(`<table style="width:100%;border-collapse:collapse;font-size:14px">`)
		b.WriteString(`<thead><tr style="background:#f5f5f5">`)
		b.WriteString(`<th style="padding:12px 16px;text-align:left;border-bottom:2px solid #0097a7;font-weight:600;white-space:nowrap">Device ID</th>`)
		b.WriteString(`<th style="padding:12px 16px;text-align:left;border-bottom:2px solid #0097a7;font-weight:600;white-space:nowrap">Address</th>`)
		b.WriteString(`<th style="padding:12px 16px;text-align:left;border-bottom:2px solid #0097a7;font-weight:600;white-space:nowrap">Platform</th>`)
		b.WriteString(`<th style="padding:12px 16px;text-align:left;border-bottom:2px solid #0097a7;font-weight:600;white-space:nowrap">Port ID</th>`)
		b.WriteString(`<th style="padding:12px 16px;text-align:left;border-bottom:2px solid #0097a7;font-weight:600;white-space:nowrap">Time</th>`)
		b.WriteString(`</tr></thead><tbody>`)

		for _, e := range cdp {
			addrs := strings.Join(e.Addresses, ", ")
			b.WriteString(`<tr style="border-bottom:1px solid #eee">`)
			b.WriteString(fmt.Sprintf(`<td style="padding:14px 16px;font-weight:600;white-space:nowrap">%s</td>`, htmlEsc(e.DeviceID)))
			b.WriteString(fmt.Sprintf(`<td style="padding:14px 16px;white-space:nowrap">%s</td>`, htmlEsc(addrs)))
			b.WriteString(fmt.Sprintf(`<td style="padding:14px 16px;white-space:nowrap">%s</td>`, htmlEsc(e.Platform)))
			b.WriteString(fmt.Sprintf(`<td style="padding:14px 16px;white-space:nowrap">%s</td>`, htmlEsc(e.PortID)))
			b.WriteString(fmt.Sprintf(`<td style="padding:14px 16px;white-space:nowrap">%s</td>`, htmlEsc(e.Timestamp)))
			b.WriteString(`</tr>`)
		}
		b.WriteString(`</tbody></table></div>`)
	}

	b.WriteString(`<div style="padding:12px 24px;background:#f5f5f5;font-size:12px;color:#999;text-align:center">`)
	b.WriteString(`Sent by <strong>Net Finder</strong></div>`)
	b.WriteString(`</div></body></html>`)
	return b.String()
}

// sendEmailStartTLS connects plain then upgrades via STARTTLS if available
func sendEmailStartTLS(cfg AlertConfig, addr, from, msg string) error {
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("dial failed: %v", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, cfg.SmtpHost)
	if err != nil {
		return fmt.Errorf("SMTP client failed: %v", err)
	}
	defer client.Close()

	// Try STARTTLS if server supports it
	if ok, _ := client.Extension("STARTTLS"); ok {
		tlsCfg := &tls.Config{ServerName: cfg.SmtpHost}
		if err := client.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("STARTTLS failed: %v", err)
		}
	}

	if cfg.SmtpAuth && cfg.SmtpUser != "" && cfg.SmtpPass != "" {
		auth := smtp.PlainAuth("", cfg.SmtpUser, cfg.SmtpPass, cfg.SmtpHost)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("SMTP auth failed: %v", err)
		}
	}

	if err := client.Mail(from); err != nil {
		return err
	}
	if err := client.Rcpt(cfg.SmtpTo); err != nil {
		return err
	}
	w, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write([]byte(msg)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return client.Quit()
}
