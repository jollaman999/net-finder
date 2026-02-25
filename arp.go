package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type ARPResult struct {
	Entries map[string][]net.HardwareAddr // IP string -> list of MACs
	mu      sync.Mutex
}

func NewARPResult() *ARPResult {
	return &ARPResult{
		Entries: make(map[string][]net.HardwareAddr),
	}
}

func (r *ARPResult) Add(ip net.IP, mac net.HardwareAddr) {
	r.mu.Lock()
	defer r.mu.Unlock()

	ipStr := ip.String()
	macStr := mac.String()

	for _, existing := range r.Entries[ipStr] {
		if existing.String() == macStr {
			return
		}
	}

	macCopy := make(net.HardwareAddr, len(mac))
	copy(macCopy, mac)
	r.Entries[ipStr] = append(r.Entries[ipStr], macCopy)
}

// subnetSourceIP returns the best source IP for ARP scanning a given subnet.
// For local subnets (containing localIP), returns localIP.
// For remote subnets, synthesizes a source IP within the subnet to bypass
// hosts with strict arp_ignore (>=2) that reject cross-subnet ARP requests.
func subnetSourceIP(subnet *net.IPNet, localIP net.IP) net.IP {
	if subnet.Contains(localIP) {
		return localIP
	}
	ones, bits := subnet.Mask.Size()
	hostBits := bits - ones
	if hostBits <= 1 {
		return localIP // /31 or /32, can't synthesize
	}
	numHosts := 1 << uint(hostBits)
	base := binary.BigEndian.Uint32(subnet.IP.To4())
	// Use second-to-last usable IP (e.g., .253 for /24) to avoid
	// common gateway addresses (.1, .254)
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, base+uint32(numHosts-3))
	return ip
}

func DiscoverSubnets(iface *net.Interface, duration time.Duration) ([]*net.IPNet, error) {
	sock, err := NewRawSocket(iface.Name)
	if err != nil {
		return nil, fmt.Errorf("소켓 열기 실패: %v", err)
	}
	defer sock.Close()

	if err := sock.SetBPFFilter(bpfFilterARP()); err != nil {
		return nil, fmt.Errorf("BPF 필터 설정 실패: %v", err)
	}

	seen := make(map[string]bool)
	deadline := time.Now().Add(duration)

	for time.Now().Before(deadline) {
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

		ip := net.IP(arp.SourceProtAddress).To4()
		if ip == nil || ip.IsUnspecified() {
			continue
		}

		subnet := fmt.Sprintf("%d.%d.%d.0/24", ip[0], ip[1], ip[2])
		if !seen[subnet] {
			seen[subnet] = true
		}
	}

	var subnets []*net.IPNet
	for s := range seen {
		_, ipnet, err := net.ParseCIDR(s)
		if err == nil {
			subnets = append(subnets, ipnet)
		}
	}

	return subnets, nil
}

func ARPScan(iface *net.Interface, localIP net.IP, localMAC net.HardwareAddr, subnets []*net.IPNet, timeout time.Duration) (*ARPResult, error) {
	sock, err := NewRawSocket(iface.Name)
	if err != nil {
		return nil, fmt.Errorf("소켓 열기 실패: %v", err)
	}
	defer sock.Close()

	if err := sock.SetBPFFilter(bpfFilterARP()); err != nil {
		return nil, fmt.Errorf("BPF 필터 설정 실패: %v", err)
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

	// Build target list with per-subnet source IPs
	// Remote subnets use a synthesized in-subnet source to bypass arp_ignore filters
	var targets []net.IP
	srcIPMap := make(map[string]net.IP) // target IP string -> source IP to use
	for _, subnet := range subnets {
		srcIP := subnetSourceIP(subnet, localIP)
		for _, ip := range expandCIDR(subnet) {
			targets = append(targets, ip)
			srcIPMap[ip.String()] = srcIP
		}
		if !subnet.Contains(localIP) {
			log.Printf("원격 서브넷 %s → 소스 IP %s 사용", subnet, srcIP)
		}
	}

	// Round 1: full sweep
	for _, ip := range targets {
		sendARPRequest(sock, iface, srcIPMap[ip.String()], localMAC, ip)
		time.Sleep(500 * time.Microsecond)
	}

	time.Sleep(timeout)

	// Rounds 2-3: retry missing IPs
	for retry := 0; retry < 2; retry++ {
		var missing []net.IP
		result.mu.Lock()
		for _, ip := range targets {
			if _, ok := result.Entries[ip.String()]; !ok {
				missing = append(missing, ip)
			}
		}
		result.mu.Unlock()

		if len(missing) == 0 {
			break
		}

		log.Printf("ARP 재시도 %d: %d개 미응답 IP", retry+1, len(missing))
		for _, ip := range missing {
			sendARPRequest(sock, iface, srcIPMap[ip.String()], localMAC, ip)
			time.Sleep(1 * time.Millisecond)
		}

		time.Sleep(2 * time.Second)
	}

	close(done)
	wg.Wait()

	// Phase 3: ICMP fallback for hosts that didn't respond to ARP
	var finalMissing []net.IP
	result.mu.Lock()
	for _, ip := range targets {
		if _, ok := result.Entries[ip.String()]; !ok {
			finalMissing = append(finalMissing, ip)
		}
	}
	result.mu.Unlock()

	if len(finalMissing) > 0 {
		icmpFallbackScan(iface, localIP, localMAC, subnets, finalMissing, result)
	}

	return result, nil
}

func sendARPRequest(sock *RawSocket, iface *net.Interface, srcIP net.IP, srcMAC net.HardwareAddr, dstIP net.IP) error {
	eth := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   srcMAC,
		SourceProtAddress: srcIP.To4(),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    dstIP.To4(),
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	if err := gopacket.SerializeLayers(buf, opts, &eth, &arp); err != nil {
		return err
	}

	return sock.WritePacket(buf.Bytes())
}

func readARPResponses(sock *RawSocket, result *ARPResult, done <-chan struct{}) {
	for {
		select {
		case <-done:
			return
		default:
		}

		data, err := sock.ReadPacket()
		if err != nil {
			select {
			case <-done:
				return
			default:
				continue
			}
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

		senderIP := net.IP(arp.SourceProtAddress).To4()
		senderMAC := net.HardwareAddr(arp.SourceHwAddress)

		if senderIP == nil || senderIP.IsUnspecified() {
			continue
		}

		switch arp.Operation {
		case layers.ARPReply:
			result.Add(senderIP, senderMAC)
		case layers.ARPRequest:
			// Passive detection: sender is claiming its IP
			if !senderIP.Equal(net.IPv4zero) {
				result.Add(senderIP, senderMAC)
			}
		}
	}
}

// icmpFallbackScan sends ICMP echo requests to hosts that didn't respond to ARP
// and captures any resulting traffic in promiscuous mode to extract their MACs.
func icmpFallbackScan(iface *net.Interface, localIP net.IP, localMAC net.HardwareAddr, subnets []*net.IPNet, missing []net.IP, result *ARPResult) {
	if len(missing) == 0 {
		return
	}

	log.Printf("ICMP 폴백 스캔: %d개 미응답 IP", len(missing))

	sock, err := NewRawSocket(iface.Name)
	if err != nil {
		log.Printf("ICMP 폴백 소켓 오류: %v", err)
		return
	}
	defer sock.Close()
	// No BPF filter — capture all traffic in promiscuous mode

	missingSet := make(map[string]bool)
	for _, ip := range missing {
		missingSet[ip.String()] = true
	}

	// Build subnet lookup for source IP selection
	findSubnet := func(ip net.IP) *net.IPNet {
		for _, sn := range subnets {
			if sn.Contains(ip) {
				return sn
			}
		}
		return nil
	}

	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)

	// Reader: capture any Ethernet frame from missing targets
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
			}

			data, err := sock.ReadPacket()
			if err != nil || data == nil {
				select {
				case <-done:
					return
				default:
					continue
				}
			}

			if len(data) < 14 {
				continue
			}

			etherType := uint16(data[12])<<8 | uint16(data[13])

			switch etherType {
			case 0x0800: // IPv4
				if len(data) < 34 {
					continue
				}
				srcIP := make(net.IP, 4)
				copy(srcIP, data[26:30])
				if missingSet[srcIP.String()] {
					srcMAC := make(net.HardwareAddr, 6)
					copy(srcMAC, data[6:12])
					result.Add(srcIP, srcMAC)
					delete(missingSet, srcIP.String())
				}
			case 0x0806: // ARP
				if len(data) < 42 {
					continue
				}
				senderIP := make(net.IP, 4)
				copy(senderIP, data[28:32])
				if missingSet[senderIP.String()] {
					senderMAC := make(net.HardwareAddr, 6)
					copy(senderMAC, data[22:28])
					result.Add(senderIP, senderMAC)
					delete(missingSet, senderIP.String())
				}
			}
		}
	}()

	broadcastMAC := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	// Round 1: send ICMP echo via broadcast MAC
	for _, ip := range missing {
		srcIP := localIP
		if sn := findSubnet(ip); sn != nil {
			srcIP = subnetSourceIP(sn, localIP)
		}
		sendICMPEcho(sock, srcIP, localMAC, broadcastMAC, ip)
		time.Sleep(500 * time.Microsecond)
	}

	time.Sleep(3 * time.Second)

	// Round 2: retry remaining via broadcast MAC
	var stillMissing []net.IP
	for _, ip := range missing {
		if missingSet[ip.String()] {
			stillMissing = append(stillMissing, ip)
		}
	}

	if len(stillMissing) > 0 {
		log.Printf("ICMP 재시도: %d개 미응답 IP", len(stillMissing))
		for _, ip := range stillMissing {
			srcIP := localIP
			if sn := findSubnet(ip); sn != nil {
				srcIP = subnetSourceIP(sn, localIP)
			}
			sendICMPEcho(sock, srcIP, localMAC, broadcastMAC, ip)
			time.Sleep(1 * time.Millisecond)
		}
		time.Sleep(2 * time.Second)
	}

	close(done)
	wg.Wait()

	found := len(missing) - len(missingSet)
	if found > 0 {
		log.Printf("ICMP 폴백: %d개 호스트 추가 발견", found)
	}
}

// sendICMPEcho sends a raw ICMP echo request at the Ethernet level.
func sendICMPEcho(sock *RawSocket, srcIP net.IP, srcMAC, dstMAC net.HardwareAddr, dstIP net.IP) error {
	eth := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ipLayer := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolICMPv4,
		SrcIP:    srcIP,
		DstIP:    dstIP,
	}

	icmpLayer := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		Id:       0xBEEF,
		Seq:      1,
	}

	payload := gopacket.Payload([]byte("netfinder"))

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	if err := gopacket.SerializeLayers(buf, opts, &eth, ipLayer, icmpLayer, payload); err != nil {
		return err
	}

	return sock.WritePacket(buf.Bytes())
}
