package protocol

import (
	"fmt"
	"net"
	"strings"
	"time"

	"net-finder/internal/models"
	"net-finder/internal/netutil"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ListenCDP listens for CDP frames on the given interface
func ListenCDP(ifaceName string, duration time.Duration, stopCh <-chan struct{}) ([]models.CDPNeighbor, error) {
	sock, err := netutil.NewRawSocket(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("CDP 소켓 열기 실패: %v", err)
	}
	defer sock.Close()

	if err := sock.SetBPFFilter(netutil.BPFFilterCDP()); err != nil {
		return nil, fmt.Errorf("CDP BPF 필터 설정 실패: %v", err)
	}

	var entries []models.CDPNeighbor
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

		entry, ok := parseCDPPacket(packet)
		if !ok {
			continue
		}

		key := entry.DeviceID + "-" + entry.PortID
		if !seen[key] {
			seen[key] = true
			entries = append(entries, entry)
		} else {
			for i, e := range entries {
				k := e.DeviceID + "-" + e.PortID
				if k == key {
					entries[i] = entry
					break
				}
			}
		}
	}

	return entries, nil
}

func parseCDPPacket(packet gopacket.Packet) (models.CDPNeighbor, bool) {
	var entry models.CDPNeighbor

	// Get source MAC
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer != nil {
		eth := ethLayer.(*layers.Ethernet)
		entry.SourceMAC = eth.SrcMAC.String()
	}

	entry.Timestamp = time.Now().Format("2006-01-02 15:04:05")

	// Parse CDP
	cdpLayer := packet.Layer(layers.LayerTypeCiscoDiscoveryInfo)
	if cdpLayer != nil {
		info := cdpLayer.(*layers.CiscoDiscoveryInfo)
		entry.DeviceID = strings.TrimSpace(info.DeviceID)
		entry.Platform = strings.TrimSpace(info.Platform)
		entry.PortID = strings.TrimSpace(info.PortID)
		entry.Version = strings.TrimSpace(info.Version)
		entry.NativeVLAN = int(info.NativeVLAN)

		seen := make(map[string]bool)
		for _, addr := range append(info.Addresses, info.MgmtAddresses...) {
			var s string
			if ip4 := net.IP(addr).To4(); ip4 != nil {
				s = ip4.String()
			} else if len(addr) > 0 {
				s = net.IP(addr).String()
			}
			if s != "" && !seen[s] {
				seen[s] = true
				entry.Addresses = append(entry.Addresses, s)
			}
		}

		return entry, entry.DeviceID != ""
	}

	// Try base CDP layer
	cdpBaseLayer := packet.Layer(layers.LayerTypeCiscoDiscovery)
	if cdpBaseLayer == nil {
		return entry, false
	}

	cdp := cdpBaseLayer.(*layers.CiscoDiscovery)
	for _, val := range cdp.Values {
		switch val.Type {
		case layers.CDPTLVDevID:
			entry.DeviceID = strings.TrimSpace(string(val.Value))
		case layers.CDPTLVPortID:
			entry.PortID = strings.TrimSpace(string(val.Value))
		case layers.CDPTLVPlatform:
			entry.Platform = strings.TrimSpace(string(val.Value))
		case layers.CDPTLVVersion:
			entry.Version = strings.TrimSpace(string(val.Value))
		case layers.CDPTLVNativeVLAN:
			if len(val.Value) >= 2 {
				entry.NativeVLAN = int(val.Value[0])<<8 | int(val.Value[1])
			}
		case layers.CDPTLVAddress:
			addrs := parseCDPAddresses(val.Value)
			entry.Addresses = append(entry.Addresses, addrs...)
		}
	}

	return entry, entry.DeviceID != ""
}

func parseCDPAddresses(data []byte) []string {
	var addrs []string
	if len(data) < 4 {
		return addrs
	}

	count := int(data[0])<<24 | int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	offset := 4

	for i := 0; i < count && offset < len(data); i++ {
		if offset+2 > len(data) {
			break
		}
		protoType := data[offset]
		protoLen := int(data[offset+1])
		offset += 2 + protoLen

		if offset+2 > len(data) {
			break
		}
		addrLen := int(data[offset])<<8 | int(data[offset+1])
		offset += 2

		if offset+addrLen > len(data) {
			break
		}

		if protoType == 1 && addrLen == 4 { // IPv4
			addr := fmt.Sprintf("%d.%d.%d.%d", data[offset], data[offset+1], data[offset+2], data[offset+3])
			addrs = append(addrs, addr)
		}
		offset += addrLen
	}

	return addrs
}
