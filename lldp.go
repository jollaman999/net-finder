package main

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ListenLLDP listens for LLDP frames on the given interface
func ListenLLDP(ifaceName string, duration time.Duration, stopCh <-chan struct{}) ([]LLDPNeighbor, error) {
	sock, err := NewRawSocket(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("LLDP 소켓 열기 실패: %v", err)
	}
	defer sock.Close()

	if err := sock.SetBPFFilter(bpfFilterLLDP()); err != nil {
		return nil, fmt.Errorf("LLDP BPF 필터 설정 실패: %v", err)
	}

	var entries []LLDPNeighbor
	seen := make(map[string]bool)
	deadline := time.Now().Add(duration)

	for time.Now().Before(deadline) {
		select {
		case <-stopCh:
			return entries, nil
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

		entry, ok := parseLLDPPacket(packet)
		if !ok {
			continue
		}

		key := entry.ChassisID + "-" + entry.PortID
		if !seen[key] {
			seen[key] = true
			entries = append(entries, entry)
		} else {
			for i, e := range entries {
				k := e.ChassisID + "-" + e.PortID
				if k == key {
					entries[i] = entry
					break
				}
			}
		}
	}

	return entries, nil
}

func parseLLDPPacket(packet gopacket.Packet) (LLDPNeighbor, bool) {
	var entry LLDPNeighbor

	// Get source MAC
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer != nil {
		eth := ethLayer.(*layers.Ethernet)
		entry.SourceMAC = eth.SrcMAC.String()
	}

	entry.Timestamp = time.Now().Format("2006-01-02 15:04:05")

	// Parse LLDP base layer
	lldpLayer := packet.Layer(layers.LayerTypeLinkLayerDiscovery)
	if lldpLayer == nil {
		return entry, false
	}
	lldp := lldpLayer.(*layers.LinkLayerDiscovery)

	entry.ChassisID = formatLLDPChassisID(lldp.ChassisID)
	entry.PortID = formatLLDPPortID(lldp.PortID)
	entry.TTL = int(lldp.TTL)

	// Parse LLDP info layer for additional TLVs
	lldpInfoLayer := packet.Layer(layers.LayerTypeLinkLayerDiscoveryInfo)
	if lldpInfoLayer != nil {
		info := lldpInfoLayer.(*layers.LinkLayerDiscoveryInfo)
		entry.SysName = info.SysName
		entry.SysDesc = info.SysDescription

		if len(info.MgmtAddress.Address) > 0 {
			switch info.MgmtAddress.Subtype {
			case layers.IANAAddressFamilyIPV4:
				entry.MgmtAddr = net.IP(info.MgmtAddress.Address).String()
			case layers.IANAAddressFamilyIPV6:
				entry.MgmtAddr = net.IP(info.MgmtAddress.Address).String()
			default:
				entry.MgmtAddr = fmt.Sprintf("%x", info.MgmtAddress.Address)
			}
		}
	}

	return entry, entry.ChassisID != ""
}

func formatLLDPChassisID(id layers.LLDPChassisID) string {
	switch id.Subtype {
	case layers.LLDPChassisIDSubTypeMACAddr:
		if len(id.ID) == 6 {
			return net.HardwareAddr(id.ID).String()
		}
	case layers.LLDPChassisIDSubTypeNetworkAddr:
		if len(id.ID) == 4 {
			return net.IP(id.ID).String()
		}
	case layers.LLDPChassisIDSubTypeLocal, layers.LLDPChassisIDSubTypeChassisComp:
		return strings.TrimSpace(string(id.ID))
	}
	if len(id.ID) > 0 {
		return strings.TrimSpace(string(id.ID))
	}
	return ""
}

func formatLLDPPortID(id layers.LLDPPortID) string {
	switch id.Subtype {
	case layers.LLDPPortIDSubtypeMACAddr:
		if len(id.ID) == 6 {
			return net.HardwareAddr(id.ID).String()
		}
	case layers.LLDPPortIDSubtypeIfaceName, layers.LLDPPortIDSubtypeLocal:
		return strings.TrimSpace(string(id.ID))
	}
	if len(id.ID) > 0 {
		return strings.TrimSpace(string(id.ID))
	}
	return ""
}
