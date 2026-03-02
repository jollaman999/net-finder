package protocol

import (
	"fmt"
	"net"
	"time"

	"net-finder/internal/models"
	"net-finder/internal/netutil"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/bpf"
)

// ListenVRRP listens for VRRP packets on the given interface
func ListenVRRP(ifaceName string, duration time.Duration, stopCh <-chan struct{}, mode ...models.IPMode) ([]models.VRRPEntry, error) {
	sock, err := netutil.NewRawSocket(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to open VRRP socket: %v", err)
	}
	defer sock.Close()

	ipMode := models.IPModeBoth
	if len(mode) > 0 {
		ipMode = mode[0]
	}
	var bpfFilter []bpf.RawInstruction
	switch ipMode {
	case models.IPModeIPv4:
		bpfFilter = netutil.BPFFilterVRRP()
	case models.IPModeIPv6:
		bpfFilter = netutil.BPFFilterVRRPv6()
	default:
		bpfFilter = netutil.BPFFilterVRRPDual()
	}
	if err := sock.SetBPFFilter(bpfFilter); err != nil {
		return nil, fmt.Errorf("failed to set VRRP BPF filter: %v", err)
	}

	var entries []models.VRRPEntry
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

func parseVRRPPacket(packet gopacket.Packet) (models.VRRPEntry, bool) {
	var entry models.VRRPEntry

	// Try gopacket VRRP layer first
	vrrpLayer := packet.Layer(layers.LayerTypeVRRP)
	if vrrpLayer != nil {
		vrrp := vrrpLayer.(*layers.VRRPv2)
		// VRRP version must be 2 or 3
		if vrrp.Version != 2 && vrrp.Version != 3 {
			return entry, false
		}
		entry.Version = int(vrrp.Version)
		entry.RouterID = int(vrrp.VirtualRtrID)
		entry.Priority = int(vrrp.Priority)
		entry.AdverInt = int(vrrp.AdverInt)

		for _, ip := range vrrp.IPAddress {
			entry.IPAddresses = append(entry.IPAddresses, ip.String())
		}
	} else {
		// Manual parse: try IPv4 first, then IPv6
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		ip6Layer := packet.Layer(layers.LayerTypeIPv6)

		var payload []byte
		var isIPv6 bool

		if ipLayer != nil {
			ip := ipLayer.(*layers.IPv4)
			payload = ip.Payload
		} else if ip6Layer != nil {
			ip6 := ip6Layer.(*layers.IPv6)
			payload = ip6.Payload
			isIPv6 = true
		} else {
			return entry, false
		}

		if len(payload) < 8 {
			return entry, false
		}

		entry.Version = int(payload[0] >> 4)
		vrrpType := int(payload[0] & 0x0f)

		// VRRP version must be 2 or 3, type must be 1 (Advertisement)
		if (entry.Version != 2 && entry.Version != 3) || vrrpType != 1 {
			return entry, false
		}

		entry.RouterID = int(payload[1])
		entry.Priority = int(payload[2])
		countIPs := int(payload[3])

		ipSize := 4
		if isIPv6 {
			ipSize = 16
		}

		if countIPs == 0 || 8+countIPs*ipSize > len(payload) {
			return entry, false
		}

		entry.AdverInt = int(payload[5])

		offset := 8
		for i := 0; i < countIPs; i++ {
			ipAddr := net.IP(payload[offset : offset+ipSize]).String()
			entry.IPAddresses = append(entry.IPAddresses, ipAddr)
			offset += ipSize
		}
	}

	// Get source IP/MAC (try IPv4 first, then IPv6)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip := ipLayer.(*layers.IPv4)
		entry.SourceIP = ip.SrcIP.String()
	} else {
		ip6Layer := packet.Layer(layers.LayerTypeIPv6)
		if ip6Layer != nil {
			ip6 := ip6Layer.(*layers.IPv6)
			entry.SourceIP = ip6.SrcIP.String()
		}
	}

	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer != nil {
		eth := ethLayer.(*layers.Ethernet)
		entry.SourceMAC = eth.SrcMAC.String()
	}

	entry.Timestamp = time.Now().Format("2006-01-02 15:04:05")
	return entry, entry.RouterID > 0
}
