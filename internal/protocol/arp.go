package protocol

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"net-finder/internal/netutil"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type ARPResult struct {
	Entries map[string][]net.HardwareAddr // IP string -> list of MACs
	Mu      sync.Mutex
}

func NewARPResult() *ARPResult {
	return &ARPResult{
		Entries: make(map[string][]net.HardwareAddr),
	}
}

func (r *ARPResult) Add(ip net.IP, mac net.HardwareAddr) {
	r.Mu.Lock()
	defer r.Mu.Unlock()

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

func DiscoverSubnets(iface *net.Interface, duration time.Duration) ([]*net.IPNet, error) {
	sock, err := netutil.NewRawSocket(iface.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to open socket: %v", err)
	}
	defer sock.Close()

	if err := sock.SetBPFFilter(netutil.BPFFilterARP()); err != nil {
		return nil, fmt.Errorf("failed to set BPF filter: %v", err)
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
	sock, err := netutil.NewRawSocket(iface.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to open socket: %v", err)
	}
	defer sock.Close()

	if err := sock.SetBPFFilter(netutil.BPFFilterARP()); err != nil {
		return nil, fmt.Errorf("failed to set BPF filter: %v", err)
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

	// ARP is L2-local: only scan subnets we are directly attached to, and always
	// use our real source IP. Never synthesize a foreign in-subnet source - that
	// is indistinguishable from ARP spoofing and trips Dynamic ARP Inspection.
	// Remote subnets are handled separately via routed L3 probes.
	var targets []net.IP
	for _, subnet := range subnets {
		if localIP == nil || !subnet.Contains(localIP) {
			continue
		}
		targets = append(targets, netutil.ExpandCIDR(subnet)...)
	}
	if len(targets) == 0 {
		close(done)
		wg.Wait()
		return result, nil
	}

	// Round 1: full sweep (globally rate-limited to stay under DAI thresholds)
	for _, ip := range targets {
		netutil.ARPAcquire()
		sendARPRequest(sock, iface, localIP, localMAC, ip)
	}

	time.Sleep(timeout)

	// Rounds 2-3: retry missing IPs
	for retry := 0; retry < 2; retry++ {
		var missing []net.IP
		result.Mu.Lock()
		for _, ip := range targets {
			if _, ok := result.Entries[ip.String()]; !ok {
				missing = append(missing, ip)
			}
		}
		result.Mu.Unlock()

		if len(missing) == 0 {
			break
		}

		for _, ip := range missing {
			netutil.ARPAcquire()
			sendARPRequest(sock, iface, localIP, localMAC, ip)
		}

		time.Sleep(2 * time.Second)
	}

	close(done)
	wg.Wait()

	// Phase 3: ICMP fallback for hosts that didn't respond to ARP
	var finalMissing []net.IP
	result.Mu.Lock()
	for _, ip := range targets {
		if _, ok := result.Entries[ip.String()]; !ok {
			finalMissing = append(finalMissing, ip)
		}
	}
	result.Mu.Unlock()

	if len(finalMissing) > 0 {
		// Collect known gateway MACs to exclude from ICMP fallback results.
		// When a host doesn't respond to ARP directly, the ICMP reply arrives
		// via the gateway, so the Ethernet source MAC is the gateway's MAC,
		// not the actual host's MAC.
		gwMACs := make(map[string]bool)
		// Exclude our own MAC (ICMP replies from self or reflected traffic)
		gwMACs[localMAC.String()] = true
		result.Mu.Lock()
		for _, sn := range subnets {
			for _, gwSuffix := range []byte{1, 254} {
				gwIP := make(net.IP, 4)
				copy(gwIP, sn.IP.To4())
				gwIP[3] = gwSuffix
				if macs, ok := result.Entries[gwIP.String()]; ok {
					for _, m := range macs {
						gwMACs[m.String()] = true
					}
				}
			}
		}
		result.Mu.Unlock()
		icmpFallbackScan(iface, localIP, localMAC, subnets, finalMissing, result, gwMACs)
	}

	return result, nil
}

// ProbeIPs sends ARP requests for a small set of IPs and returns observed MACs per IP.
// Used for quick re-verification of conflicts and host liveness.
func ProbeIPs(iface *net.Interface, localIP net.IP, localMAC net.HardwareAddr, subnets []*net.IPNet, ips []net.IP, timeout time.Duration) (*ARPResult, error) {
	if len(ips) == 0 {
		return NewARPResult(), nil
	}

	sock, err := netutil.NewRawSocket(iface.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to open socket: %v", err)
	}
	defer sock.Close()

	if err := sock.SetBPFFilter(netutil.BPFFilterARP()); err != nil {
		return nil, fmt.Errorf("failed to set BPF filter: %v", err)
	}

	result := NewARPResult()
	done := make(chan struct{})

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		readARPResponses(sock, result, done)
	}()

	time.Sleep(50 * time.Millisecond)

	// Only ARP-probe IPs in a subnet we are attached to, always with our real
	// source IP. Remote IPs cannot be reached by ARP and must never be spoofed.
	attached := func(ip net.IP) bool {
		for _, sn := range subnets {
			if sn.Contains(ip) && localIP != nil && sn.Contains(localIP) {
				return true
			}
		}
		return false
	}
	var localIPs []net.IP
	for _, ip := range ips {
		if attached(ip) {
			localIPs = append(localIPs, ip)
		}
	}
	if len(localIPs) == 0 {
		close(done)
		wg.Wait()
		return result, nil
	}

	// Round 1: full sweep (rate-limited)
	for _, ip := range localIPs {
		netutil.ARPAcquire()
		sendARPRequest(sock, iface, localIP, localMAC, ip)
	}
	time.Sleep(timeout)

	// Rounds 2-3: retry only missing IPs
	for retry := 0; retry < 2; retry++ {
		var missing []net.IP
		result.Mu.Lock()
		for _, ip := range localIPs {
			if _, ok := result.Entries[ip.String()]; !ok {
				missing = append(missing, ip)
			}
		}
		result.Mu.Unlock()

		if len(missing) == 0 {
			break
		}

		for _, ip := range missing {
			netutil.ARPAcquire()
			sendARPRequest(sock, iface, localIP, localMAC, ip)
		}
		time.Sleep(timeout)
	}

	close(done)
	wg.Wait()
	return result, nil
}

func sendARPRequest(sock *netutil.RawSocket, iface *net.Interface, srcIP net.IP, srcMAC net.HardwareAddr, dstIP net.IP) error {
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

func readARPResponses(sock *netutil.RawSocket, result *ARPResult, done <-chan struct{}) {
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
func icmpFallbackScan(iface *net.Interface, localIP net.IP, localMAC net.HardwareAddr, subnets []*net.IPNet, missing []net.IP, result *ARPResult, gwMACs map[string]bool) {
	if len(missing) == 0 {
		return
	}

	log.Printf("ICMP fallback scan: %d unresponsive IPs", len(missing))

	sock, err := netutil.NewRawSocket(iface.Name)
	if err != nil {
		log.Printf("ICMP fallback socket error: %v", err)
		return
	}
	defer sock.Close()
	// No BPF filter - capture all traffic in promiscuous mode

	missingSet := make(map[string]bool)
	for _, ip := range missing {
		missingSet[ip.String()] = true
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
					if gwMACs[srcMAC.String()] {
						continue
					}
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
					if gwMACs[senderMAC.String()] {
						continue
					}
					result.Add(senderIP, senderMAC)
					delete(missingSet, senderIP.String())
				}
			}
		}
	}()

	broadcastMAC := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	// Round 1: send ICMP echo via broadcast MAC (rate-limited, real source IP)
	for _, ip := range missing {
		netutil.ARPAcquire()
		sendICMPEcho(sock, localIP, localMAC, broadcastMAC, ip)
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
		for _, ip := range stillMissing {
			netutil.ARPAcquire()
			sendICMPEcho(sock, localIP, localMAC, broadcastMAC, ip)
		}
		time.Sleep(2 * time.Second)
	}

	close(done)
	wg.Wait()

	found := len(missing) - len(missingSet)
	if found > 0 {
		log.Printf("ICMP fallback: %d additional hosts found", found)
	}
}

// sendICMPEcho sends a raw ICMP echo request at the Ethernet level.
func sendICMPEcho(sock *netutil.RawSocket, srcIP net.IP, srcMAC, dstMAC net.HardwareAddr, dstIP net.IP) error {
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
