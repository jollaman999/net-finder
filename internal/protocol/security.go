package protocol

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"net-finder/internal/models"
	"net-finder/internal/netutil"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// macEvent records a MAC change for flapping detection
type macEvent struct {
	mac  string
	time time.Time
}

// MonitorARP monitors ARP traffic for spoofing indicators
func MonitorARP(ifaceName string, baseline map[string][]string, gatewayIP string, duration time.Duration, stopCh <-chan struct{}) ([]models.ARPSpoofAlert, error) {
	sock, err := netutil.NewRawSocket(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to open ARP monitor socket: %v", err)
	}
	defer sock.Close()

	if err := sock.SetBPFFilter(netutil.BPFFilterARP()); err != nil {
		return nil, fmt.Errorf("failed to set ARP monitor BPF filter: %v", err)
	}

	// key -> alert index + packet count
	alertIndex := make(map[string]int)
	var alerts []models.ARPSpoofAlert
	var mu sync.Mutex

	// MAC flapping detection: IP -> recent MAC change history
	macHistory := make(map[string][]macEvent) // IP -> recent events
	lastMAC := make(map[string]string)        // IP -> last seen MAC
	flapAlerted := make(map[string]bool)      // IP -> already alerted for flapping

	deadline := time.Now().Add(duration)

	for time.Now().Before(deadline) {
		select {
		case <-stopCh:
			return alerts, nil
		default:
		}

		data, err := sock.ReadPacket()
		if err != nil {
			continue
		}
		if data == nil {
			continue
		}

		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)

		arpLayer := packet.Layer(layers.LayerTypeARP)
		if arpLayer == nil {
			continue
		}
		arp, ok := arpLayer.(*layers.ARP)
		if !ok {
			continue
		}

		// Extract Ethernet layer for MAC mismatch detection
		ethLayer := packet.Layer(layers.LayerTypeEthernet)
		if ethLayer == nil {
			continue
		}
		eth := ethLayer.(*layers.Ethernet)

		senderIP := net.IP(arp.SourceProtAddress).To4()
		senderMAC := net.HardwareAddr(arp.SourceHwAddress)

		if senderIP == nil || senderIP.IsUnspecified() {
			continue
		}

		ipStr := senderIP.String()
		macStr := senderMAC.String()
		ethMAC := eth.SrcMAC.String()
		now := time.Now()
		nowStr := now.Format("2006-01-02 15:04:05")

		mu.Lock()

		// 1) MAC mismatch detection: Ethernet src MAC != ARP sender MAC
		if ethMAC != macStr {
			key := "mismatch:" + ipStr + ":" + ethMAC + ":" + macStr
			if idx, exists := alertIndex[key]; exists {
				alerts[idx].Count++
				alerts[idx].Timestamp = nowStr
			} else {
				alertIndex[key] = len(alerts)
				alerts = append(alerts, models.ARPSpoofAlert{
					IP:        ipStr,
					OldMAC:    ethMAC,
					NewMAC:    macStr,
					AlertType: "mac_mismatch",
					Severity:  "critical",
					Message:   fmt.Sprintf("Ethernet src MAC (%s) != ARP sender MAC (%s)", ethMAC, macStr),
					Count:     1,
					FirstSeen: nowStr,
					Timestamp: nowStr,
				})
			}
		}

		// 2) Baseline MAC change detection (existing "spoof" logic)
		if knownMACs, ok := baseline[ipStr]; ok {
			found := false
			for _, km := range knownMACs {
				if km == macStr {
					found = true
					break
				}
			}
			if !found {
				key := "spoof:" + ipStr + ":" + macStr
				if idx, exists := alertIndex[key]; exists {
					alerts[idx].Count++
					alerts[idx].Timestamp = nowStr
				} else {
					severity := "warning"
					if ipStr == gatewayIP {
						severity = "critical"
					}
					alertIndex[key] = len(alerts)
					macsCopy := make([]string, len(knownMACs))
					copy(macsCopy, knownMACs)
					alerts = append(alerts, models.ARPSpoofAlert{
						IP:        ipStr,
						OldMACs:   macsCopy,
						NewMAC:    macStr,
						AlertType: "spoof",
						Severity:  severity,
						Count:     1,
						FirstSeen: nowStr,
						Timestamp: nowStr,
					})
				}
			}

			// 3) MAC flapping detection (only for baseline IPs)
			if prev, hasPrev := lastMAC[ipStr]; hasPrev && prev != macStr {
				macHistory[ipStr] = append(macHistory[ipStr], macEvent{mac: macStr, time: now})
				// Prune events older than 30 seconds
				cutoff := now.Add(-30 * time.Second)
				events := macHistory[ipStr]
				start := 0
				for start < len(events) && events[start].time.Before(cutoff) {
					start++
				}
				macHistory[ipStr] = events[start:]

				if len(macHistory[ipStr]) >= 3 && !flapAlerted[ipStr] {
					flapAlerted[ipStr] = true
					key := "flap:" + ipStr
					alertIndex[key] = len(alerts)
					flapMACs := make([]string, len(knownMACs))
					copy(flapMACs, knownMACs)
					alerts = append(alerts, models.ARPSpoofAlert{
						IP:        ipStr,
						OldMACs:   flapMACs,
						NewMAC:    macStr,
						AlertType: "mac_flap",
						Severity:  "critical",
						Message:   fmt.Sprintf("MAC changed %d times in 30s for %s", len(macHistory[ipStr]), ipStr),
						Count:     len(macHistory[ipStr]),
						FirstSeen: nowStr,
						Timestamp: nowStr,
					})
				}
			}
			lastMAC[ipStr] = macStr
		}

		mu.Unlock()
	}

	return alerts, nil
}

// MonitorNDP monitors NDP traffic for IPv6 spoofing indicators
func MonitorNDP(ifaceName string, baseline map[string][]string, gatewayIPv6 string, duration time.Duration, stopCh <-chan struct{}) ([]models.NDPSpoofAlert, error) {
	sock, err := netutil.NewRawSocket(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to open NDP monitor socket: %v", err)
	}
	defer sock.Close()

	if err := sock.SetBPFFilter(netutil.BPFFilterNDP()); err != nil {
		return nil, fmt.Errorf("failed to set NDP monitor BPF filter: %v", err)
	}

	alertIndex := make(map[string]int)
	var alerts []models.NDPSpoofAlert
	var mu sync.Mutex

	// MAC flapping detection
	macHistory := make(map[string][]macEvent)
	lastMAC := make(map[string]string)
	flapAlerted := make(map[string]bool)

	deadline := time.Now().Add(duration)

	for time.Now().Before(deadline) {
		select {
		case <-stopCh:
			return alerts, nil
		default:
		}

		data, err := sock.ReadPacket()
		if err != nil || data == nil {
			continue
		}

		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)

		// Only process NA (type 136)
		icmpLayer := packet.Layer(layers.LayerTypeICMPv6)
		if icmpLayer == nil {
			continue
		}
		icmp := icmpLayer.(*layers.ICMPv6)
		if icmp.TypeCode.Type() != layers.ICMPv6TypeNeighborAdvertisement {
			continue
		}

		naLayer := packet.Layer(layers.LayerTypeICMPv6NeighborAdvertisement)
		if naLayer == nil {
			continue
		}
		na := naLayer.(*layers.ICMPv6NeighborAdvertisement)

		ethLayer := packet.Layer(layers.LayerTypeEthernet)
		if ethLayer == nil {
			continue
		}
		eth := ethLayer.(*layers.Ethernet)

		ipStr := na.TargetAddress.String()
		ethMAC := eth.SrcMAC.String()
		now := time.Now()
		nowStr := now.Format("2006-01-02 15:04:05")

		// Extract Target Link-Layer Address from NA options
		var optionMAC string
		for _, opt := range na.Options {
			if opt.Type == layers.ICMPv6OptTargetAddress && len(opt.Data) >= 6 {
				optionMAC = net.HardwareAddr(opt.Data[:6]).String()
				break
			}
		}

		mu.Lock()

		// 1) MAC mismatch detection: Ethernet src MAC != NA option MAC
		if optionMAC != "" && ethMAC != optionMAC {
			key := "mismatch:" + ipStr + ":" + ethMAC + ":" + optionMAC
			if idx, exists := alertIndex[key]; exists {
				alerts[idx].Count++
				alerts[idx].Timestamp = nowStr
			} else {
				alertIndex[key] = len(alerts)
				alerts = append(alerts, models.NDPSpoofAlert{
					IP:        ipStr,
					OldMAC:    ethMAC,
					NewMAC:    optionMAC,
					AlertType: "mac_mismatch",
					Severity:  "critical",
					Message:   fmt.Sprintf("Ethernet src MAC (%s) != NA option MAC (%s)", ethMAC, optionMAC),
					Count:     1,
					FirstSeen: nowStr,
					Timestamp: nowStr,
				})
			}
		}

		// Use Ethernet MAC as the advertised MAC for baseline/flapping checks
		macStr := ethMAC

		// 2) Baseline MAC change detection (existing "spoof" logic)
		if knownMACs, ok := baseline[ipStr]; ok {
			found := false
			for _, km := range knownMACs {
				if km == macStr {
					found = true
					break
				}
			}
			if !found {
				key := "spoof:" + ipStr + ":" + macStr
				if idx, exists := alertIndex[key]; exists {
					alerts[idx].Count++
					alerts[idx].Timestamp = nowStr
				} else {
					severity := "warning"
					if ipStr == gatewayIPv6 {
						severity = "critical"
					}
					alertIndex[key] = len(alerts)
					ndpMACsCopy := make([]string, len(knownMACs))
					copy(ndpMACsCopy, knownMACs)
					alerts = append(alerts, models.NDPSpoofAlert{
						IP:        ipStr,
						OldMACs:   ndpMACsCopy,
						NewMAC:    macStr,
						AlertType: "spoof",
						Severity:  severity,
						Count:     1,
						FirstSeen: nowStr,
						Timestamp: nowStr,
					})
				}
			}

			// 3) MAC flapping detection (only for baseline IPs)
			if prev, hasPrev := lastMAC[ipStr]; hasPrev && prev != macStr {
				macHistory[ipStr] = append(macHistory[ipStr], macEvent{mac: macStr, time: now})
				cutoff := now.Add(-30 * time.Second)
				events := macHistory[ipStr]
				start := 0
				for start < len(events) && events[start].time.Before(cutoff) {
					start++
				}
				macHistory[ipStr] = events[start:]

				if len(macHistory[ipStr]) >= 3 && !flapAlerted[ipStr] {
					flapAlerted[ipStr] = true
					key := "flap:" + ipStr
					ndpFlapMACs := make([]string, len(knownMACs))
					copy(ndpFlapMACs, knownMACs)
					alertIndex[key] = len(alerts)
					alerts = append(alerts, models.NDPSpoofAlert{
						IP:        ipStr,
						OldMACs:   ndpFlapMACs,
						NewMAC:    macStr,
						AlertType: "mac_flap",
						Severity:  "critical",
						Message:   fmt.Sprintf("MAC changed %d times in 30s for %s", len(macHistory[ipStr]), ipStr),
						Count:     len(macHistory[ipStr]),
						FirstSeen: nowStr,
						Timestamp: nowStr,
					})
				}
			}
			lastMAC[ipStr] = macStr
		}

		mu.Unlock()
	}

	return alerts, nil
}

// CheckDNSSpoofing queries multiple DNS servers and compares results
func CheckDNSSpoofing(dnsServers []string) []models.DNSSpoofAlert {
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

	var alerts []models.DNSSpoofAlert

	for _, domain := range testDomains {
		type dnsResult struct {
			server  string
			ips     []string
			elapsed time.Duration
			err     error
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
				alerts = append(alerts, models.DNSSpoofAlert{
					Domain:    domain,
					Server1:   results[i].server,
					Response1: strings.Join(results[i].ips, ", "),
					AlertType: "fast_response",
					Severity:  "warning",
					Message:   fmt.Sprintf("Abnormally fast DNS response: %s (server: %s, response time: %v) - possible local spoofing", domain, results[i].server, results[i].elapsed),
					Timestamp: time.Now().Format("2006-01-02 15:04:05"),
				})
			}

			for j := i + 1; j < len(results); j++ {
				if results[j].err != nil {
					continue
				}

				// Compare IP sets
				if !ipSetsOverlap(results[i].ips, results[j].ips) {
					alerts = append(alerts, models.DNSSpoofAlert{
						Domain:    domain,
						Server1:   results[i].server,
						Response1: strings.Join(results[i].ips, ", "),
						Server2:   results[j].server,
						Response2: strings.Join(results[j].ips, ", "),
						AlertType: "mismatch",
						Severity:  "critical",
						Message:   fmt.Sprintf("DNS response mismatch: %s (server %s: %s vs server %s: %s)", domain, results[i].server, strings.Join(results[i].ips, ","), results[j].server, strings.Join(results[j].ips, ",")),
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
