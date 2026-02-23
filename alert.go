package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/smtp"
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
	mu      sync.RWMutex
	configs []AlertConfig
}

// NewAlertManager creates a new AlertManager
func NewAlertManager() *AlertManager {
	return &AlertManager{}
}

// GetConfigs returns all alert configurations
func (am *AlertManager) GetConfigs() []AlertConfig {
	am.mu.RLock()
	defer am.mu.RUnlock()
	result := make([]AlertConfig, len(am.configs))
	copy(result, am.configs)
	return result
}

// AddConfig adds a new alert configuration
func (am *AlertManager) AddConfig(cfg AlertConfig) {
	am.mu.Lock()
	defer am.mu.Unlock()
	if cfg.ID == "" {
		cfg.ID = fmt.Sprintf("%d", time.Now().UnixNano())
	}
	am.configs = append(am.configs, cfg)
}

// DeleteConfig removes an alert configuration by ID
func (am *AlertManager) DeleteConfig(id string) bool {
	am.mu.Lock()
	defer am.mu.Unlock()
	for i, c := range am.configs {
		if c.ID == id {
			am.configs = append(am.configs[:i], am.configs[i+1:]...)
			return true
		}
	}
	return false
}

// SendConflictAlert sends alerts for a conflict to all matching configs
func (am *AlertManager) SendConflictAlert(conflict ConflictEntry) {
	am.mu.RLock()
	configs := make([]AlertConfig, len(am.configs))
	copy(configs, am.configs)
	am.mu.RUnlock()

	for _, cfg := range configs {
		if !matchesSubnet(cfg, conflict) {
			continue
		}
		if err := sendEmail(cfg, conflict); err != nil {
			log.Printf("알림 발송 실패 [%s]: %v", cfg.ID, err)
		}
	}
}

// TestAlert sends a test alert using the given config
func (am *AlertManager) TestAlert(cfg AlertConfig) error {
	testConflict := ConflictEntry{
		IP:      "192.168.1.100",
		MACs:    []string{"AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02"},
		Vendors: []string{"Vendor A", "Vendor B"},
		Subnet:  "192.168.1.0/24",
	}
	return sendEmail(cfg, testConflict)
}

func matchesSubnet(cfg AlertConfig, conflict ConflictEntry) bool {
	if len(cfg.Subnets) == 0 {
		return true
	}
	for _, s := range cfg.Subnets {
		if s == conflict.Subnet {
			return true
		}
	}
	return false
}

func buildAlertMessage(conflict ConflictEntry) string {
	return fmt.Sprintf("[Net Finder] IP Conflict Detected\nIP: %s\nSubnet: %s\nMACs: %s\nVendors: %s\nTime: %s",
		conflict.IP,
		conflict.Subnet,
		strings.Join(conflict.MACs, ", "),
		strings.Join(conflict.Vendors, ", "),
		time.Now().Format(time.RFC3339),
	)
}

func sendEmail(cfg AlertConfig, conflict ConflictEntry) error {
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

	subject := fmt.Sprintf("[Net Finder] IP Conflict: %s", conflict.IP)
	body := buildAlertMessage(conflict)
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s",
		from, cfg.SmtpTo, subject, body)

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
