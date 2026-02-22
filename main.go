package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"time"
)

const (
	colorRed    = "\033[91m"
	colorGreen  = "\033[92m"
	colorYellow = "\033[93m"
	colorCyan   = "\033[96m"
	colorBold   = "\033[1m"
	colorReset  = "\033[0m"
)

func main() {
	ifaceName := flag.String("i", "", "네트워크 인터페이스 (미지정시 자동 감지)")
	subnetStr := flag.String("s", "", "스캔할 서브넷 (콤마 구분, 예: 192.168.110.0/24,192.168.130.0/24)")
	discoverDuration := flag.Duration("discover", 5*time.Second, "대역 자동 탐색 감청 시간 (-s 미지정시)")
	arpTimeout := flag.Duration("arp-timeout", 3*time.Second, "ARP 응답 대기 시간")
	dhcpTimeout := flag.Duration("dhcp-timeout", 5*time.Second, "DHCP 응답 대기 시간")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "%sIP 충돌 감지 & 네트워크 스캐너%s\n\n", colorBold, colorReset)
		fmt.Fprintf(os.Stderr, "Usage:\n  sudo %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  sudo %s -i eth0 -s 192.168.110.0/24,192.168.130.0/24\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  sudo %s -s 192.168.110.0/24,192.168.130.0/24\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  sudo %s\n", os.Args[0])
	}

	flag.Parse()

	if os.Getuid() != 0 {
		fmt.Fprintf(os.Stderr, "%s이 프로그램은 root 권한이 필요합니다. sudo로 실행해주세요.%s\n", colorRed, colorReset)
		os.Exit(1)
	}

	// Banner
	fmt.Println()
	fmt.Printf("%s╔══════════════════════════════════════════════════════════╗%s\n", colorCyan, colorReset)
	fmt.Printf("%s║         IP 충돌 감지 & 네트워크 스캐너                  ║%s\n", colorCyan, colorReset)
	fmt.Printf("%s╚══════════════════════════════════════════════════════════╝%s\n", colorCyan, colorReset)
	fmt.Println()

	// Interface
	iface, err := getInterface(*ifaceName)
	if err != nil {
		log.Fatalf("인터페이스 감지 실패: %v", err)
	}

	localIP, localMAC, err := getInterfaceAddr(iface)
	if err != nil {
		log.Fatalf("인터페이스 주소 가져오기 실패: %v", err)
	}

	var subnets []*net.IPNet
	if *subnetStr != "" {
		subnets = parseSubnets(*subnetStr, iface)
	} else {
		fmt.Printf("%s=== 대역 자동 탐색 ===%s\n", colorBold, colorReset)
		fmt.Printf("  ARP 트래픽 감청 중 (%v)...\n", *discoverDuration)

		discovered, err := DiscoverSubnets(iface, *discoverDuration)
		if err != nil {
			log.Fatalf("대역 탐색 실패: %v", err)
		}

		localSubnets := parseSubnets("", iface)
		seen := make(map[string]bool)
		for _, s := range localSubnets {
			seen[s.String()] = true
			subnets = append(subnets, s)
		}
		for _, s := range discovered {
			if !seen[s.String()] {
				seen[s.String()] = true
				subnets = append(subnets, s)
			}
		}

		fmt.Printf("  탐색 완료: %s%d개 대역%s 감지\n\n", colorGreen, len(subnets), colorReset)
	}

	if len(subnets) == 0 {
		log.Fatal("스캔할 서브넷이 없습니다. -s 옵션으로 서브넷을 지정해주세요.")
	}

	// Load OUI
	fmt.Println("OUI 데이터베이스 로딩 중...")
	oui, err := LoadOUI()
	if err != nil {
		log.Printf("OUI 로드 실패 (벤더 정보 없이 진행): %v", err)
		oui = &OUIDatabase{
			Vendors:  make(map[string]string),
			prefix2:  make(map[[2]byte]string),
			apiCache: make(map[string]string),
		}
	}
	defer oui.saveAPICache() // 종료 시 API 조회 결과 캐시 저장
	fmt.Printf("OUI 데이터베이스: %s%d%s개 벤더 로드 완료\n", colorGreen, len(oui.Vendors), colorReset)

	// Scan info
	subnetStrs := make([]string, len(subnets))
	for i, s := range subnets {
		subnetStrs[i] = s.String()
	}
	fmt.Println()
	fmt.Printf("  인터페이스: %s%s%s\n", colorBold, iface.Name, colorReset)
	fmt.Printf("  로컬 IP:    %s\n", localIP)
	fmt.Printf("  로컬 MAC:   %s\n", oui.FormatMAC(localMAC))
	fmt.Printf("  스캔 대역:  %s\n", strings.Join(subnetStrs, ", "))
	fmt.Println()

	// ARP Scan
	fmt.Printf("%s=== ARP 스캔 ===%s\n", colorBold, colorReset)
	result, err := ARPScan(iface, localIP, localMAC, subnets, *arpTimeout)
	if err != nil {
		log.Fatalf("ARP 스캔 실패: %v", err)
	}
	displayARPResults(result, subnets, oui)

	// DHCP Detection
	fmt.Printf("\n%s=== DHCP 서버 감지 ===%s\n", colorBold, colorReset)
	servers, err := DetectDHCP(iface, localMAC, *dhcpTimeout)
	if err != nil {
		log.Printf("DHCP 감지 실패: %v", err)
	} else {
		displayDHCPResults(servers, oui)
	}

	fmt.Println()
}

func displayARPResults(result *ARPResult, subnets []*net.IPNet, oui *OUIDatabase) {
	type subnetGroup struct {
		subnet    *net.IPNet
		hosts     []string
		bonds     []string
		conflicts []string
	}

	groups := make(map[string]*subnetGroup)
	var groupOrder []string

	for _, subnet := range subnets {
		key := subnet.String()
		groups[key] = &subnetGroup{subnet: subnet}
		groupOrder = append(groupOrder, key)
	}

	sort.Slice(groupOrder, func(i, j int) bool {
		a := groups[groupOrder[i]].subnet.IP.To4()
		b := groups[groupOrder[j]].subnet.IP.To4()
		if a == nil || b == nil {
			return groupOrder[i] < groupOrder[j]
		}
		return binary.BigEndian.Uint32(a) < binary.BigEndian.Uint32(b)
	})

	var ungrouped []string

	for ipStr := range result.Entries {
		ip := net.ParseIP(ipStr)
		placed := false
		for _, key := range groupOrder {
			g := groups[key]
			if g.subnet.Contains(ip) {
				macs := result.Entries[ipStr]
				if len(macs) > 1 {
					devGroups := groupMACsByDevice(macs)
					if len(devGroups) == 1 {
						g.bonds = append(g.bonds, ipStr)
					} else {
						g.conflicts = append(g.conflicts, ipStr)
					}
				} else {
					g.hosts = append(g.hosts, ipStr)
				}
				placed = true
				break
			}
		}
		if !placed {
			ungrouped = append(ungrouped, ipStr)
		}
	}

	totalHosts := 0
	totalBonds := 0
	totalConflicts := 0
	for _, g := range groups {
		totalHosts += len(g.hosts) + len(g.bonds) + len(g.conflicts)
		totalBonds += len(g.bonds)
		totalConflicts += len(g.conflicts)
	}
	totalHosts += len(ungrouped)

	fmt.Printf("\n  발견된 호스트: %s%d개%s\n", colorGreen, totalHosts, colorReset)

	for _, key := range groupOrder {
		g := groups[key]
		sortIPStrings(g.hosts)
		sortIPStrings(g.bonds)
		sortIPStrings(g.conflicts)

		count := len(g.hosts) + len(g.bonds) + len(g.conflicts)
		if count == 0 {
			continue
		}

		fmt.Printf("\n  %s[ %s ] ── %d개 호스트%s\n", colorBold, key, count, colorReset)
		fmt.Println("  " + strings.Repeat("─", 70))

		allIPs := make([]string, 0, count)
		allIPs = append(allIPs, g.hosts...)
		allIPs = append(allIPs, g.bonds...)
		allIPs = append(allIPs, g.conflicts...)
		sortIPStrings(allIPs)

		bondSet := make(map[string]bool)
		for _, ip := range g.bonds {
			bondSet[ip] = true
		}
		conflictSet := make(map[string]bool)
		for _, ip := range g.conflicts {
			conflictSet[ip] = true
		}

		for _, ipStr := range allIPs {
			macs := result.Entries[ipStr]
			if conflictSet[ipStr] {
				for _, mac := range macs {
					fmt.Printf("  %-18s %s%s (IP 충돌)%s\n", ipStr, colorRed, oui.FormatMAC(mac), colorReset)
				}
			} else if bondSet[ipStr] {
				fmt.Printf("  %-18s %s%s (Bond/Dual-NIC)%s\n", ipStr, colorCyan, oui.FormatMAC(macs[0]), colorReset)
			} else {
				fmt.Printf("  %-18s %s\n", ipStr, oui.FormatMAC(macs[0]))
			}
		}
	}

	if len(ungrouped) > 0 {
		sortIPStrings(ungrouped)
		fmt.Printf("\n  %s[ 기타 ] ── %d개 호스트%s\n", colorBold, len(ungrouped), colorReset)
		fmt.Println("  " + strings.Repeat("─", 70))
		for _, ipStr := range ungrouped {
			macs := result.Entries[ipStr]
			if len(macs) > 1 {
				for _, mac := range macs {
					fmt.Printf("  %-18s %s%s (IP 충돌)%s\n", ipStr, colorRed, oui.FormatMAC(mac), colorReset)
				}
			} else {
				fmt.Printf("  %-18s %s\n", ipStr, oui.FormatMAC(macs[0]))
			}
		}
	}

	if totalBonds > 0 {
		fmt.Printf("\n  %sBond/Dual-NIC 감지: %d건%s (동일 장비 - 충돌 아님)\n", colorCyan, totalBonds, colorReset)
		fmt.Println("  " + strings.Repeat("─", 70))

		for _, key := range groupOrder {
			g := groups[key]
			for _, ipStr := range g.bonds {
				macs := result.Entries[ipStr]
				fmt.Printf("  %-18s %s\n", ipStr, oui.Lookup(macs[0]))
				for _, mac := range macs {
					fmt.Printf("                     %s\n", oui.FormatMAC(mac))
				}
			}
		}
	}

	if totalConflicts > 0 {
		fmt.Printf("\n  %s%s!! IP 충돌 감지: %d건%s\n", colorBold, colorRed, totalConflicts, colorReset)
		fmt.Println("  " + strings.Repeat("=", 70))

		for _, key := range groupOrder {
			g := groups[key]
			if len(g.conflicts) == 0 {
				continue
			}
			fmt.Printf("\n  %s[ %s ]%s\n", colorBold, key, colorReset)
			for _, ipStr := range g.conflicts {
				macs := result.Entries[ipStr]
				devGroups := groupMACsByDevice(macs)
				fmt.Printf("  %s충돌 IP: %s - %d개 장비%s\n", colorYellow, ipStr, len(devGroups), colorReset)
				for i, dg := range devGroups {
					if len(dg) > 1 {
						fmt.Printf("    [장비 %d] %s (Bond/Dual-NIC %d포트)\n", i+1, oui.FormatMAC(dg[0]), len(dg))
						for _, mac := range dg {
							fmt.Printf("             %s\n", mac)
						}
					} else {
						fmt.Printf("    [장비 %d] %s\n", i+1, oui.FormatMAC(dg[0]))
					}
				}
			}
		}
	} else {
		fmt.Printf("\n  %sIP 충돌이 감지되지 않았습니다.%s\n", colorGreen, colorReset)
	}
}

func displayDHCPResults(servers []DHCPServerInfo, oui *OUIDatabase) {
	if len(servers) == 0 {
		fmt.Printf("  %sDHCP 서버가 감지되지 않았습니다.%s\n", colorYellow, colorReset)
		return
	}

	fmt.Printf("\n  감지된 DHCP 서버: %s%d개%s\n", colorCyan, len(servers), colorReset)
	fmt.Println("  " + strings.Repeat("─", 70))

	for i, s := range servers {
		fmt.Printf("\n  %s[DHCP 서버 %d]%s\n", colorBold, i+1, colorReset)
		if s.ServerIP != nil {
			fmt.Printf("    서버 IP:    %s\n", s.ServerIP)
		}
		if s.ServerMAC != nil {
			fmt.Printf("    서버 MAC:   %s\n", oui.FormatMAC(s.ServerMAC))
		}
		if s.OfferedIP != nil {
			fmt.Printf("    제공 IP:    %s\n", s.OfferedIP)
		}
		if s.SubnetMask != nil {
			fmt.Printf("    서브넷:     %s\n", net.IP(s.SubnetMask))
		}
		if s.Router != nil {
			fmt.Printf("    게이트웨이: %s\n", s.Router)
		}
		if len(s.DNS) > 0 {
			dnsStrs := make([]string, len(s.DNS))
			for j, dns := range s.DNS {
				dnsStrs[j] = dns.String()
			}
			fmt.Printf("    DNS:        %s\n", strings.Join(dnsStrs, ", "))
		}
		if s.LeaseTime > 0 {
			fmt.Printf("    임대시간:   %v\n", time.Duration(s.LeaseTime)*time.Second)
		}
	}

	if len(servers) > 1 {
		fmt.Printf("\n  %s%s!! 주의: 다수의 DHCP 서버가 감지되었습니다!%s\n", colorBold, colorRed, colorReset)
		fmt.Printf("  %s   비인가(Rogue) DHCP 서버가 존재할 수 있습니다.%s\n", colorYellow, colorReset)
	}
}
