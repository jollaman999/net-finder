package main

import (
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ListenVRRP listens for VRRP packets on the given interface
func ListenVRRP(ifaceName string, duration time.Duration, stopCh <-chan struct{}) ([]VRRPEntry, error) {
	sock, err := NewRawSocket(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("VRRP 소켓 열기 실패: %v", err)
	}
	defer sock.Close()

	if err := sock.SetBPFFilter(bpfFilterVRRP()); err != nil {
		return nil, fmt.Errorf("VRRP BPF 필터 설정 실패: %v", err)
	}

	var entries []VRRPEntry
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

		entry, ok := parseVRRPPacket(packet)
		if !ok {
			continue
		}

		key := fmt.Sprintf("%d-%s", entry.RouterID, entry.SourceIP)
		if !seen[key] {
			seen[key] = true
			entries = append(entries, entry)
		} else {
			for i, e := range entries {
				k := fmt.Sprintf("%d-%s", e.RouterID, e.SourceIP)
				if k == key {
					entries[i] = entry
					break
				}
			}
		}
	}

	return entries, nil
}

func parseVRRPPacket(packet gopacket.Packet) (VRRPEntry, bool) {
	var entry VRRPEntry

	// Try gopacket VRRP layer first
	vrrpLayer := packet.Layer(layers.LayerTypeVRRP)
	if vrrpLayer != nil {
		vrrp := vrrpLayer.(*layers.VRRPv2)
		entry.Version = int(vrrp.Version)
		entry.RouterID = int(vrrp.VirtualRtrID)
		entry.Priority = int(vrrp.Priority)
		entry.AdverInt = int(vrrp.AdverInt)

		for _, ip := range vrrp.IPAddress {
			entry.IPAddresses = append(entry.IPAddresses, ip.String())
		}
	} else {
		// Manual parse from IPv4 payload
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			return entry, false
		}
		ip := ipLayer.(*layers.IPv4)
		payload := ip.Payload
		if len(payload) < 8 {
			return entry, false
		}

		entry.Version = int(payload[0] >> 4)
		// type := payload[0] & 0x0f
		entry.RouterID = int(payload[1])
		entry.Priority = int(payload[2])
		countIPs := int(payload[3])
		entry.AdverInt = int(payload[5])

		offset := 8
		for i := 0; i < countIPs && offset+4 <= len(payload); i++ {
			ipAddr := fmt.Sprintf("%d.%d.%d.%d", payload[offset], payload[offset+1], payload[offset+2], payload[offset+3])
			entry.IPAddresses = append(entry.IPAddresses, ipAddr)
			offset += 4
		}
	}

	// Get source IP/MAC
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip := ipLayer.(*layers.IPv4)
		entry.SourceIP = ip.SrcIP.String()
	}

	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer != nil {
		eth := ethLayer.(*layers.Ethernet)
		entry.SourceMAC = eth.SrcMAC.String()
	}

	entry.Timestamp = time.Now().Format("2006-01-02 15:04:05")
	return entry, entry.RouterID > 0
}
