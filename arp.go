package main

import (
	"fmt"
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

	localNet := localSubnet(localIP, subnets)

	for _, subnet := range subnets {
		ips := expandCIDR(subnet)
		isLocal := localNet != nil && localNet.Contains(subnet.IP)

		for _, ip := range ips {
			if isLocal {
				sendARPRequest(sock, iface, localIP, localMAC, ip)
			} else {
				sendARPProbe(sock, iface, localMAC, ip)
			}
			time.Sleep(500 * time.Microsecond)
		}
	}

	time.Sleep(timeout)
	close(done)
	wg.Wait()

	return result, nil
}

func localSubnet(localIP net.IP, subnets []*net.IPNet) *net.IPNet {
	for _, subnet := range subnets {
		if subnet.Contains(localIP) {
			return subnet
		}
	}
	return nil
}

func sendARPProbe(sock *RawSocket, iface *net.Interface, srcMAC net.HardwareAddr, dstIP net.IP) error {
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
		SourceProtAddress: net.IPv4zero.To4(),
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
