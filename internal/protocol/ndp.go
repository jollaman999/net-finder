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

// NDPResult holds NDP scan results: IP -> list of MACs
type NDPResult struct {
	Entries map[string][]net.HardwareAddr
	Mu      sync.Mutex
}

func NewNDPResult() *NDPResult {
	return &NDPResult{
		Entries: make(map[string][]net.HardwareAddr),
	}
}

func (r *NDPResult) Add(ip net.IP, mac net.HardwareAddr) {
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

// NDPScan discovers IPv6 hosts by sending ICMPv6 Echo Request to ff02::1
// (all-nodes multicast) and collecting responses.
func NDPScan(iface *net.Interface, localIPv6 net.IP, localMAC net.HardwareAddr,
	subnets []*net.IPNet, timeout time.Duration) (*NDPResult, error) {

	sock, err := netutil.NewRawSocket(iface.Name)
	if err != nil {
		return nil, fmt.Errorf("NDP 소켓 열기 실패: %v", err)
	}
	defer sock.Close()

	if err := sock.SetBPFFilter(netutil.BPFFilterICMPv6()); err != nil {
		return nil, fmt.Errorf("NDP BPF 필터 설정 실패: %v", err)
	}

	result := NewNDPResult()
	done := make(chan struct{})

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		readNDPResponses(sock, result, localMAC, done)
	}()

	time.Sleep(100 * time.Millisecond)

	// Send ICMPv6 Echo Request to ff02::1 (all-nodes multicast)
	allNodesMAC := net.HardwareAddr{0x33, 0x33, 0x00, 0x00, 0x00, 0x01}
	allNodesIP := net.ParseIP("ff02::1")

	srcIP := localIPv6
	if srcIP == nil {
		// Use link-local from interface if no global
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() == nil && ipnet.IP.IsLinkLocalUnicast() {
				srcIP = ipnet.IP
				break
			}
		}
	}
	if srcIP == nil {
		close(done)
		wg.Wait()
		return nil, fmt.Errorf("IPv6 주소를 찾을 수 없습니다")
	}

	// Round 1: multicast ping
	if err := sendICMPv6Echo(sock, srcIP, localMAC, allNodesMAC, allNodesIP); err != nil {
		log.Printf("NDP 멀티캐스트 전송 실패: %v", err)
	}

	time.Sleep(timeout)

	// Round 2: retry
	if err := sendICMPv6Echo(sock, srcIP, localMAC, allNodesMAC, allNodesIP); err != nil {
		log.Printf("NDP 멀티캐스트 재시도 실패: %v", err)
	}

	time.Sleep(2 * time.Second)

	close(done)
	wg.Wait()

	return result, nil
}

func sendICMPv6Echo(sock *netutil.RawSocket, srcIP net.IP, srcMAC, dstMAC net.HardwareAddr, dstIP net.IP) error {
	eth := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv6,
	}

	ipv6 := &layers.IPv6{
		Version:    6,
		HopLimit:   255,
		SrcIP:      srcIP,
		DstIP:      dstIP,
		NextHeader: layers.IPProtocolICMPv6,
	}

	icmpv6 := &layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoRequest, 0),
	}
	icmpv6.SetNetworkLayerForChecksum(ipv6)

	echo := &layers.ICMPv6Echo{
		Identifier: 0xBEEF,
		SeqNumber:  1,
	}

	payload := gopacket.Payload([]byte("netfinder"))

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	if err := gopacket.SerializeLayers(buf, opts, &eth, ipv6, icmpv6, echo, payload); err != nil {
		return err
	}

	return sock.WritePacket(buf.Bytes())
}

func readNDPResponses(sock *netutil.RawSocket, result *NDPResult, localMAC net.HardwareAddr, done <-chan struct{}) {
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

		ethLayer := packet.Layer(layers.LayerTypeEthernet)
		if ethLayer == nil {
			continue
		}
		eth := ethLayer.(*layers.Ethernet)

		// Skip our own packets
		if eth.SrcMAC.String() == localMAC.String() {
			continue
		}

		ip6Layer := packet.Layer(layers.LayerTypeIPv6)
		if ip6Layer == nil {
			continue
		}
		ip6 := ip6Layer.(*layers.IPv6)

		icmpLayer := packet.Layer(layers.LayerTypeICMPv6)
		if icmpLayer == nil {
			continue
		}
		icmp := icmpLayer.(*layers.ICMPv6)

		switch icmp.TypeCode.Type() {
		case layers.ICMPv6TypeEchoReply:
			// Echo reply: source IP responded
			srcIP := make(net.IP, len(ip6.SrcIP))
			copy(srcIP, ip6.SrcIP)
			srcMAC := make(net.HardwareAddr, len(eth.SrcMAC))
			copy(srcMAC, eth.SrcMAC)
			result.Add(srcIP, srcMAC)

		case layers.ICMPv6TypeNeighborAdvertisement:
			// NA: extract target IP from ICMPv6 payload
			naLayer := packet.Layer(layers.LayerTypeICMPv6NeighborAdvertisement)
			if naLayer != nil {
				na := naLayer.(*layers.ICMPv6NeighborAdvertisement)
				targetIP := make(net.IP, len(na.TargetAddress))
				copy(targetIP, na.TargetAddress)
				srcMAC := make(net.HardwareAddr, len(eth.SrcMAC))
				copy(srcMAC, eth.SrcMAC)
				result.Add(targetIP, srcMAC)
			}

		case layers.ICMPv6TypeNeighborSolicitation:
			// NS: sender is advertising its own IP
			srcIP := ip6.SrcIP
			if !srcIP.IsUnspecified() {
				ipCopy := make(net.IP, len(srcIP))
				copy(ipCopy, srcIP)
				srcMAC := make(net.HardwareAddr, len(eth.SrcMAC))
				copy(srcMAC, eth.SrcMAC)
				result.Add(ipCopy, srcMAC)
			}
		}
	}
}

// SolicitedNodeMulticast computes the solicited-node multicast address for an IPv6 address.
func SolicitedNodeMulticast(ip net.IP) net.IP {
	ip = ip.To16()
	if ip == nil {
		return nil
	}
	return net.IP{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0xff, ip[13], ip[14], ip[15]}
}

// SolicitedNodeMAC computes the multicast MAC for a solicited-node multicast address.
func SolicitedNodeMAC(ip net.IP) net.HardwareAddr {
	ip = ip.To16()
	if ip == nil {
		return nil
	}
	return net.HardwareAddr{0x33, 0x33, 0xff, ip[13], ip[14], ip[15]}
}
