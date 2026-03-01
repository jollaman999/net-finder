package protocol

import (
	"fmt"
	"net"
	"time"

	"net-finder/internal/models"
	"net-finder/internal/netutil"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func DetectDHCP(iface *net.Interface, localMAC net.HardwareAddr, timeout time.Duration) ([]models.DHCPServerInfo, error) {
	sock, err := netutil.NewRawSocket(iface.Name)
	if err != nil {
		return nil, fmt.Errorf("소켓 열기 실패: %v", err)
	}
	defer sock.Close()

	if err := sock.SetBPFFilter(netutil.BPFFilterDHCP()); err != nil {
		return nil, fmt.Errorf("BPF 필터 설정 실패: %v", err)
	}

	xid := uint32(time.Now().UnixNano() & 0xFFFFFFFF)

	if err := sendDHCPDiscover(sock, iface, localMAC, xid); err != nil {
		return nil, fmt.Errorf("DHCP Discover 전송 실패: %v", err)
	}

	return listenDHCPOffers(sock, xid, timeout)
}

func sendDHCPDiscover(sock *netutil.RawSocket, iface *net.Interface, srcMAC net.HardwareAddr, xid uint32) error {
	eth := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ipv4 := layers.IPv4{
		Version:  4,
		TTL:      128,
		SrcIP:    net.IPv4(0, 0, 0, 0),
		DstIP:    net.IPv4(255, 255, 255, 255),
		Protocol: layers.IPProtocolUDP,
	}

	udp := layers.UDP{
		SrcPort: 68,
		DstPort: 67,
	}
	udp.SetNetworkLayerForChecksum(&ipv4)

	dhcpOpts := layers.DHCPOptions{
		{
			Type:   layers.DHCPOptMessageType,
			Data:   []byte{byte(layers.DHCPMsgTypeDiscover)},
			Length: 1,
		},
		{
			Type:   layers.DHCPOptParamsRequest,
			Data:   []byte{1, 3, 6, 15, 28, 51},
			Length: 6,
		},
	}

	dhcp := layers.DHCPv4{
		Operation:    layers.DHCPOpRequest,
		HardwareType: layers.LinkTypeEthernet,
		HardwareLen:  6,
		Xid:          xid,
		Flags:        0x8000, // Broadcast flag
		ClientHWAddr: srcMAC,
		Options:      dhcpOpts,
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	if err := gopacket.SerializeLayers(buf, opts, &eth, &ipv4, &udp, &dhcp); err != nil {
		return err
	}

	return sock.WritePacket(buf.Bytes())
}

func listenDHCPOffers(sock *netutil.RawSocket, xid uint32, timeout time.Duration) ([]models.DHCPServerInfo, error) {
	var servers []models.DHCPServerInfo
	seen := make(map[string]bool)

	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		data, err := sock.ReadPacket()
		if err != nil {
			continue
		}
		if data == nil {
			continue
		}

		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)

		dhcpLayer := packet.Layer(layers.LayerTypeDHCPv4)
		if dhcpLayer == nil {
			continue
		}

		dhcp, ok := dhcpLayer.(*layers.DHCPv4)
		if !ok || dhcp.Operation != layers.DHCPOpReply {
			continue
		}

		if dhcp.Xid != xid {
			continue
		}

		msgType := getDHCPMessageType(dhcp.Options)
		if msgType != layers.DHCPMsgTypeOffer {
			continue
		}

		server := models.DHCPServerInfo{
			OfferedIP: dhcp.YourClientIP,
		}

		ethLayer := packet.Layer(layers.LayerTypeEthernet)
		if ethLayer != nil {
			eth, _ := ethLayer.(*layers.Ethernet)
			server.ServerMAC = make(net.HardwareAddr, len(eth.SrcMAC))
			copy(server.ServerMAC, eth.SrcMAC)
		}

		for _, opt := range dhcp.Options {
			switch opt.Type {
			case layers.DHCPOptServerID:
				server.ServerIP = make(net.IP, len(opt.Data))
				copy(server.ServerIP, opt.Data)
			case layers.DHCPOptSubnetMask:
				server.SubnetMask = make(net.IPMask, len(opt.Data))
				copy(server.SubnetMask, opt.Data)
			case layers.DHCPOptRouter:
				if len(opt.Data) >= 4 {
					server.Router = make(net.IP, 4)
					copy(server.Router, opt.Data[:4])
				}
			case layers.DHCPOptDNS:
				for i := 0; i+3 < len(opt.Data); i += 4 {
					dns := make(net.IP, 4)
					copy(dns, opt.Data[i:i+4])
					server.DNS = append(server.DNS, dns)
				}
			case layers.DHCPOptLeaseTime:
				if len(opt.Data) == 4 {
					server.LeaseTime = uint32(opt.Data[0])<<24 |
						uint32(opt.Data[1])<<16 |
						uint32(opt.Data[2])<<8 |
						uint32(opt.Data[3])
				}
			}
		}

		if server.ServerIP == nil {
			server.ServerIP = dhcp.NextServerIP
		}

		key := server.ServerIP.String()
		if !seen[key] {
			seen[key] = true
			servers = append(servers, server)
		}
	}

	return servers, nil
}

func getDHCPMessageType(options layers.DHCPOptions) layers.DHCPMsgType {
	for _, opt := range options {
		if opt.Type == layers.DHCPOptMessageType && len(opt.Data) > 0 {
			return layers.DHCPMsgType(opt.Data[0])
		}
	}
	return 0
}
