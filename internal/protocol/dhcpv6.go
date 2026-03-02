package protocol

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"net-finder/internal/models"
	"net-finder/internal/netutil"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// DetectDHCPv6 sends a DHCPv6 Solicit and listens for Advertise responses.
func DetectDHCPv6(iface *net.Interface, localMAC net.HardwareAddr,
	localIPv6 net.IP, timeout time.Duration) ([]models.DHCPv6ServerInfo, error) {

	sock, err := netutil.NewRawSocket(iface.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to open DHCPv6 socket: %v", err)
	}
	defer sock.Close()

	if err := sock.SetBPFFilter(netutil.BPFFilterDHCPv6()); err != nil {
		return nil, fmt.Errorf("failed to set DHCPv6 BPF filter: %v", err)
	}

	// Use link-local address as source
	srcIP := localIPv6
	if srcIP == nil {
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() == nil && ipnet.IP.IsLinkLocalUnicast() {
				srcIP = ipnet.IP
				break
			}
		}
	}
	if srcIP == nil {
		return nil, fmt.Errorf("DHCPv6: no IPv6 link-local address found")
	}

	xid := uint32(time.Now().UnixNano() & 0xFFFFFF) // 24-bit transaction ID

	if err := sendDHCPv6Solicit(sock, iface, localMAC, srcIP, xid); err != nil {
		return nil, fmt.Errorf("failed to send DHCPv6 Solicit: %v", err)
	}

	return listenDHCPv6Advertise(sock, xid, timeout)
}

func sendDHCPv6Solicit(sock *netutil.RawSocket, iface *net.Interface, srcMAC net.HardwareAddr, srcIP net.IP, xid uint32) error {
	// DHCPv6 all-relay-agents-and-servers multicast
	dstMAC := net.HardwareAddr{0x33, 0x33, 0x00, 0x01, 0x00, 0x02}
	dstIP := net.ParseIP("ff02::1:2")

	eth := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv6,
	}

	ipv6 := &layers.IPv6{
		Version:    6,
		HopLimit:   1,
		SrcIP:      srcIP,
		DstIP:      dstIP,
		NextHeader: layers.IPProtocolUDP,
	}

	udp := &layers.UDP{
		SrcPort: 546,
		DstPort: 547,
	}
	udp.SetNetworkLayerForChecksum(ipv6)

	// Build DHCPv6 Solicit message manually
	// Message type (1 byte) + Transaction ID (3 bytes) + Options
	dhcpPayload := buildDHCPv6Solicit(srcMAC, xid)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	if err := gopacket.SerializeLayers(buf, opts, &eth, ipv6, udp, gopacket.Payload(dhcpPayload)); err != nil {
		return err
	}

	return sock.WritePacket(buf.Bytes())
}

func buildDHCPv6Solicit(clientMAC net.HardwareAddr, xid uint32) []byte {
	var pkt []byte

	// Message type: Solicit (1) + Transaction ID (3 bytes)
	pkt = append(pkt, 1) // Solicit
	pkt = append(pkt, byte(xid>>16), byte(xid>>8), byte(xid))

	// Option: Client Identifier (option 1)
	// DUID-LL: type=3, hwtype=1 (Ethernet), MAC
	duid := []byte{0x00, 0x03, 0x00, 0x01} // DUID-LL, Ethernet
	duid = append(duid, clientMAC...)
	pkt = appendDHCPv6Option(pkt, 1, duid)

	// Option: Elapsed Time (option 8) = 0
	pkt = appendDHCPv6Option(pkt, 8, []byte{0x00, 0x00})

	// Option: Option Request (option 6) - request DNS(23), Domain Search(24)
	oro := []byte{0x00, 23, 0x00, 24}
	pkt = appendDHCPv6Option(pkt, 6, oro)

	return pkt
}

func appendDHCPv6Option(pkt []byte, code uint16, data []byte) []byte {
	opt := make([]byte, 4)
	binary.BigEndian.PutUint16(opt[0:2], code)
	binary.BigEndian.PutUint16(opt[2:4], uint16(len(data)))
	pkt = append(pkt, opt...)
	pkt = append(pkt, data...)
	return pkt
}

func listenDHCPv6Advertise(sock *netutil.RawSocket, xid uint32, timeout time.Duration) ([]models.DHCPv6ServerInfo, error) {
	var servers []models.DHCPv6ServerInfo
	seen := make(map[string]bool)

	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		data, err := sock.ReadPacket()
		if err != nil || data == nil {
			continue
		}

		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)

		// Get source MAC from Ethernet
		var serverMAC net.HardwareAddr
		ethLayer := packet.Layer(layers.LayerTypeEthernet)
		if ethLayer != nil {
			eth := ethLayer.(*layers.Ethernet)
			serverMAC = make(net.HardwareAddr, len(eth.SrcMAC))
			copy(serverMAC, eth.SrcMAC)
		}

		// Get source IP from IPv6
		var serverIP net.IP
		ip6Layer := packet.Layer(layers.LayerTypeIPv6)
		if ip6Layer != nil {
			ip6 := ip6Layer.(*layers.IPv6)
			serverIP = make(net.IP, len(ip6.SrcIP))
			copy(serverIP, ip6.SrcIP)
		}

		// Get UDP payload
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer == nil {
			continue
		}
		payload := udpLayer.(*layers.UDP).Payload
		if len(payload) < 4 {
			continue
		}

		// DHCPv6 message type (1 byte) + Transaction ID (3 bytes)
		msgType := payload[0]
		respXid := uint32(payload[1])<<16 | uint32(payload[2])<<8 | uint32(payload[3])

		// Only accept Advertise (2) or Reply (7) with matching XID
		if (msgType != 2 && msgType != 7) || respXid != xid {
			continue
		}

		server := parseDHCPv6Options(payload[4:])
		if serverIP != nil {
			server.ServerIP = serverIP
		}
		if serverMAC != nil {
			server.ServerMAC = serverMAC
		}

		key := server.ServerIP.String()
		if !seen[key] {
			seen[key] = true
			servers = append(servers, server)
		}
	}

	return servers, nil
}

func parseDHCPv6Options(data []byte) models.DHCPv6ServerInfo {
	var info models.DHCPv6ServerInfo
	offset := 0

	for offset+4 <= len(data) {
		optCode := binary.BigEndian.Uint16(data[offset : offset+2])
		optLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		offset += 4

		if offset+optLen > len(data) {
			break
		}

		optData := data[offset : offset+optLen]

		switch optCode {
		case 7: // Preference
			if len(optData) >= 1 {
				info.Preference = int(optData[0])
			}
		case 23: // DNS Recursive Name Server
			for i := 0; i+16 <= len(optData); i += 16 {
				dns := make(net.IP, 16)
				copy(dns, optData[i:i+16])
				info.DNSServers = append(info.DNSServers, dns)
			}
		case 24: // Domain Search List
			info.DomainSearch = parseDHCPv6DomainList(optData)
		case 3: // IA_NA - contains valid lifetime
			if len(optData) >= 16 {
				info.ValidLifetime = binary.BigEndian.Uint32(optData[8:12])
			}
		}

		offset += optLen
	}

	return info
}

func parseDHCPv6DomainList(data []byte) []string {
	var domains []string
	pos := 0
	for pos < len(data) {
		var parts []string
		for pos < len(data) {
			labelLen := int(data[pos])
			pos++
			if labelLen == 0 {
				break
			}
			if pos+labelLen > len(data) {
				return domains
			}
			parts = append(parts, string(data[pos:pos+labelLen]))
			pos += labelLen
		}
		if len(parts) > 0 {
			domains = append(domains, strings.Join(parts, "."))
		}
	}
	return domains
}
