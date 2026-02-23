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
	Subnets  []string `json:"subnets"`  // monitored subnets (empty = all)
	Type     string   `json:"type"`     // "email"
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

// TestAlert sends a test alert using the given config
func (am *AlertManager) TestAlert(cfg AlertConfig) error {
	testConflicts := []ConflictEntry{
		{IP: "192.168.1.100", MACs: []string{"AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02"}, Vendors: []string{"Vendor A", "Vendor B"}, Subnet: "192.168.1.0/24"},
		{IP: "192.168.1.200", MACs: []string{"11:22:33:44:55:01", "11:22:33:44:55:02", "11:22:33:44:55:03"}, Vendors: []string{"Vendor C", "Vendor D", "Vendor E"}, Subnet: "192.168.1.0/24"},
	}
	subject := fmt.Sprintf("[Net Finder] IP Conflict — %s (%d)", "192.168.1.0/24", len(testConflicts))
	body := buildHTMLReport("192.168.1.0/24", testConflicts)
	return sendEmailHTML(cfg, subject, body)
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

func buildHTMLReport(subnet string, conflicts []ConflictEntry) string {
	now := time.Now().Format("2006-01-02 15:04:05")

	var b strings.Builder
	b.WriteString(`<!DOCTYPE html><html><head><meta charset="UTF-8"></head><body style="margin:0;padding:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f5f5f5">`)
	b.WriteString(`<div style="max-width:640px;margin:20px auto;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.1)">`)

	// Header
	b.WriteString(`<div style="background:#d32f2f;color:#fff;padding:20px 24px">`)
	b.WriteString(`<h2 style="margin:0 0 4px;font-size:18px">IP Conflict Detected</h2>`)
	b.WriteString(fmt.Sprintf(`<div style="font-size:13px;opacity:0.9">Subnet: <strong>%s</strong> &nbsp;|&nbsp; %d conflict(s) &nbsp;|&nbsp; %s</div>`,
		htmlEsc(subnet), len(conflicts), htmlEsc(now)))
	b.WriteString(`</div>`)

	// Table
	b.WriteString(`<div style="padding:16px 24px">`)
	b.WriteString(`<table style="width:100%;border-collapse:collapse;font-size:13px">`)
	b.WriteString(`<thead><tr style="background:#f5f5f5">`)
	b.WriteString(`<th style="padding:10px 12px;text-align:left;border-bottom:2px solid #d32f2f;font-weight:600">IP</th>`)
	b.WriteString(`<th style="padding:10px 12px;text-align:left;border-bottom:2px solid #d32f2f;font-weight:600">Hostname</th>`)
	b.WriteString(`<th style="padding:10px 12px;text-align:left;border-bottom:2px solid #d32f2f;font-weight:600">MAC Address</th>`)
	b.WriteString(`<th style="padding:10px 12px;text-align:left;border-bottom:2px solid #d32f2f;font-weight:600">Vendor</th>`)
	b.WriteString(`</tr></thead><tbody>`)

	for _, c := range conflicts {
		hostname := c.Hostname
		if hostname == "" {
			hostname = "-"
		}
		macHTML := strings.Join(macsToHTML(c.MACs), "<br>")
		vendorHTML := strings.Join(vendorsToHTML(c.Vendors), "<br>")

		b.WriteString(`<tr style="border-bottom:1px solid #eee">`)
		b.WriteString(fmt.Sprintf(`<td style="padding:10px 12px;font-weight:600">%s</td>`, htmlEsc(c.IP)))
		b.WriteString(fmt.Sprintf(`<td style="padding:10px 12px;color:#666">%s</td>`, htmlEsc(hostname)))
		b.WriteString(fmt.Sprintf(`<td style="padding:10px 12px;font-family:'Courier New',monospace;font-size:12px">%s</td>`, macHTML))
		b.WriteString(fmt.Sprintf(`<td style="padding:10px 12px">%s</td>`, vendorHTML))
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
