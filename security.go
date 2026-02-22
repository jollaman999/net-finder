package main

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// MonitorARP monitors ARP traffic for spoofing indicators
func MonitorARP(ifaceName string, baseline map[string]string, gatewayIP string, duration time.Duration, stopCh <-chan struct{}) ([]ARPSpoofAlert, error) {
	handle, err := pcap.OpenLive(ifaceName, 65536, true, 500*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("ARP 모니터 pcap 열기 실패: %v", err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter("arp"); err != nil {
		return nil, fmt.Errorf("ARP 모니터 BPF 필터 설정 실패: %v", err)
	}

	var alerts []ARPSpoofAlert
	var mu sync.Mutex

	// Track MAC changes for flapping detection
	macHistory := make(map[string][]macChange)

	deadline := time.Now().Add(duration)
	src := gopacket.NewPacketSource(handle, handle.LinkType())

	for time.Now().Before(deadline) {
		select {
		case <-stopCh:
			return alerts, nil
		default:
		}

		packet, err := src.NextPacket()
		if err != nil {
			continue
		}

		arpLayer := packet.Layer(layers.LayerTypeARP)
		if arpLayer == nil {
			continue
		}
		arp, ok := arpLayer.(*layers.ARP)
		if !ok {
			continue
		}

		senderIP := net.IP(arp.SourceProtAddress).To4()
		senderMAC := net.HardwareAddr(arp.SourceHwAddress)

		if senderIP == nil || senderIP.IsUnspecified() {
			continue
		}

		ipStr := senderIP.String()
		macStr := senderMAC.String()
		now := time.Now()

		mu.Lock()

		// Check for gratuitous ARP (sender IP == target IP in request)
		if arp.Operation == layers.ARPRequest {
			targetIP := net.IP(arp.DstProtAddress).To4()
			if targetIP != nil && senderIP.Equal(targetIP) {
				alerts = append(alerts, ARPSpoofAlert{
					IP:        ipStr,
					NewMAC:    macStr,
					AlertType: "gratuitous",
					Severity:  "warning",
					Message:   fmt.Sprintf("Gratuitous ARP 감지: %s (%s)", ipStr, macStr),
					Timestamp: now.Format("2006-01-02 15:04:05"),
				})
			}
		}

		// Check for MAC change from baseline
		if expectedMAC, ok := baseline[ipStr]; ok {
			if expectedMAC != macStr {
				severity := "warning"
				if ipStr == gatewayIP {
					severity = "critical"
				}

				alerts = append(alerts, ARPSpoofAlert{
					IP:        ipStr,
					OldMAC:    expectedMAC,
					NewMAC:    macStr,
					AlertType: "mac_change",
					Severity:  severity,
					Message:   fmt.Sprintf("MAC 변경 감지: %s (%s → %s)", ipStr, expectedMAC, macStr),
					Timestamp: now.Format("2006-01-02 15:04:05"),
				})

				// Update baseline
				baseline[ipStr] = macStr
			}
		}

		// Track MAC flapping (3+ changes in 60 seconds)
		macHistory[ipStr] = append(macHistory[ipStr], macChange{mac: macStr, t: now})
		// Clean old entries
		var recent []macChange
		for _, mc := range macHistory[ipStr] {
			if now.Sub(mc.t) <= 60*time.Second {
				recent = append(recent, mc)
			}
		}
		macHistory[ipStr] = recent

		// Count distinct MACs in window
		distinctMACs := make(map[string]bool)
		for _, mc := range recent {
			distinctMACs[mc.mac] = true
		}
		if len(distinctMACs) >= 3 {
			severity := "warning"
			if ipStr == gatewayIP {
				severity = "critical"
			}
			alerts = append(alerts, ARPSpoofAlert{
				IP:        ipStr,
				AlertType: "flapping",
				Severity:  severity,
				Message:   fmt.Sprintf("MAC Flapping 감지: %s (60초 내 %d회 변경)", ipStr, len(distinctMACs)),
				Timestamp: now.Format("2006-01-02 15:04:05"),
			})
			// Reset to avoid repeated alerts
			macHistory[ipStr] = nil
		}

		mu.Unlock()
	}

	return alerts, nil
}

type macChange struct {
	mac string
	t   time.Time
}

// CheckDNSSpoofing queries multiple DNS servers and compares results
func CheckDNSSpoofing(dnsServers []string) []DNSSpoofAlert {
	if len(dnsServers) < 2 {
		return nil
	}

	// Deduplicate servers
	serverSet := make(map[string]bool)
	var servers []string
	for _, s := range dnsServers {
		if !serverSet[s] {
			serverSet[s] = true
			servers = append(servers, s)
		}
	}

	if len(servers) < 2 {
		return nil
	}

	testDomains := []string{
		"google.com",
		"naver.com",
		"cloudflare.com",
		"github.com",
	}

	var alerts []DNSSpoofAlert

	for _, domain := range testDomains {
		type dnsResult struct {
			server   string
			ips      []string
			elapsed  time.Duration
			err      error
		}

		results := make([]dnsResult, len(servers))
		var wg sync.WaitGroup

		for i, server := range servers {
			wg.Add(1)
			go func(idx int, srv string) {
				defer wg.Done()
				resolver := &net.Resolver{
					PreferGo: true,
					Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
						d := net.Dialer{Timeout: 3 * time.Second}
						return d.DialContext(ctx, "udp", srv+":53")
					},
				}

				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				start := time.Now()
				addrs, err := resolver.LookupHost(ctx, domain)
				elapsed := time.Since(start)
				cancel()

				results[idx] = dnsResult{
					server:  srv,
					ips:     addrs,
					elapsed: elapsed,
					err:     err,
				}
			}(i, server)
		}
		wg.Wait()

		// Compare results between servers
		for i := 0; i < len(results); i++ {
			if results[i].err != nil {
				continue
			}

			// Check for suspiciously fast response (< 1ms)
			if results[i].elapsed < 1*time.Millisecond {
				alerts = append(alerts, DNSSpoofAlert{
					Domain:    domain,
					Server1:   results[i].server,
					Response1: strings.Join(results[i].ips, ", "),
					AlertType: "fast_response",
					Severity:  "warning",
					Message:   fmt.Sprintf("DNS 응답이 비정상적으로 빠름: %s (서버: %s, 응답시간: %v) - 로컬 스푸핑 의심", domain, results[i].server, results[i].elapsed),
					Timestamp: time.Now().Format("2006-01-02 15:04:05"),
				})
			}

			for j := i + 1; j < len(results); j++ {
				if results[j].err != nil {
					continue
				}

				// Compare IP sets
				if !ipSetsOverlap(results[i].ips, results[j].ips) {
					alerts = append(alerts, DNSSpoofAlert{
						Domain:    domain,
						Server1:   results[i].server,
						Response1: strings.Join(results[i].ips, ", "),
						Server2:   results[j].server,
						Response2: strings.Join(results[j].ips, ", "),
						AlertType: "mismatch",
						Severity:  "critical",
						Message:   fmt.Sprintf("DNS 응답 불일치: %s (서버 %s: %s vs 서버 %s: %s)", domain, results[i].server, strings.Join(results[i].ips, ","), results[j].server, strings.Join(results[j].ips, ",")),
						Timestamp: time.Now().Format("2006-01-02 15:04:05"),
					})
				}
			}
		}
	}

	return alerts
}

// ipSetsOverlap checks if two IP lists have any common elements
func ipSetsOverlap(a, b []string) bool {
	if len(a) == 0 || len(b) == 0 {
		return true // Don't alert on empty results
	}

	// Normalize and sort
	setA := make(map[string]bool)
	for _, ip := range a {
		setA[normalizeIP(ip)] = true
	}
	for _, ip := range b {
		if setA[normalizeIP(ip)] {
			return true
		}
	}
	return false
}

func normalizeIP(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed != nil {
		return parsed.String()
	}
	return ip
}

