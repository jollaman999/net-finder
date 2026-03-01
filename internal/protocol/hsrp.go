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

// HSRP state names
var hsrpStateNames = map[byte]string{
	0:  "Initial",
	1:  "Learn",
	2:  "Listen",
	4:  "Speak",
	8:  "Standby",
	16: "Active",
}

// ListenHSRP listens for HSRP packets on the given interface
func ListenHSRP(ifaceName string, duration time.Duration, stopCh <-chan struct{}) ([]models.HSRPEntry, error) {
	sock, err := netutil.NewRawSocket(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("HSRP 소켓 열기 실패: %v", err)
	}
	defer sock.Close()

	if err := sock.SetBPFFilter(netutil.BPFFilterHSRP()); err != nil {
		return nil, fmt.Errorf("HSRP BPF 필터 설정 실패: %v", err)
	}

	var entries []models.HSRPEntry
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

		entry, ok := parseHSRPPacket(packet)
		if !ok {
			continue
		}

		key := fmt.Sprintf("%d-%d-%s", entry.Version, entry.Group, entry.SourceIP)
		if !seen[key] {
			seen[key] = true
			entries = append(entries, entry)
		} else {
			// Update existing entry with newer timestamp
			for i, e := range entries {
				k := fmt.Sprintf("%d-%d-%s", e.Version, e.Group, e.SourceIP)
				if k == key {
					entries[i] = entry
					break
				}
			}
		}
	}

	return entries, nil
}

func parseHSRPPacket(packet gopacket.Packet) (models.HSRPEntry, bool) {
	var entry models.HSRPEntry

	// Get source IP
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return entry, false
	}
	ip := ipLayer.(*layers.IPv4)
	entry.SourceIP = ip.SrcIP.String()

	// Get source MAC
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer != nil {
		eth := ethLayer.(*layers.Ethernet)
		entry.SourceMAC = eth.SrcMAC.String()
	}

	// Get UDP payload
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return entry, false
	}
	payload := udpLayer.(*layers.UDP).Payload
	if len(payload) < 1 {
		return entry, false
	}

	entry.Timestamp = time.Now().Format("2006-01-02 15:04:05")

	// Determine HSRP version
	if payload[0] == 0x00 {
		// HSRP v1 - fixed 20-byte format
		return parseHSRPv1(payload, entry)
	} else if payload[0] == 0x02 {
		// HSRP v2 - TLV format
		return parseHSRPv2(payload, entry)
	}

	return entry, false
}

func parseHSRPv1(data []byte, entry models.HSRPEntry) (models.HSRPEntry, bool) {
	if len(data) < 20 {
		return entry, false
	}

	entry.Version = 1
	// byte 0: version (0x00)
	// byte 1: opcode (0=Hello, 1=Coup, 2=Resign)
	// byte 2: state
	state := data[2]
	if name, ok := hsrpStateNames[state]; ok {
		entry.State = name
	} else {
		entry.State = fmt.Sprintf("Unknown(%d)", state)
	}

	// byte 3: hello time
	entry.HelloTime = int(data[3])
	// byte 4: hold time
	entry.HoldTime = int(data[4])
	// byte 5: priority
	entry.Priority = int(data[5])
	// byte 6: group
	entry.Group = int(data[6])

	// bytes 8-11: auth (skip)
	// bytes 12-15: virtual IP
	if len(data) >= 20 {
		entry.VirtualIP = net.IP(data[16:20]).String()
	}

	return entry, true
}

func parseHSRPv2(data []byte, entry models.HSRPEntry) (models.HSRPEntry, bool) {
	if len(data) < 4 {
		return entry, false
	}

	entry.Version = 2

	// TLV parsing
	offset := 0
	for offset+3 < len(data) {
		tlvType := data[offset]
		tlvLen := int(data[offset+1])<<8 | int(data[offset+2])

		if offset+3+tlvLen > len(data) {
			break
		}

		tlvData := data[offset+3 : offset+3+tlvLen]
		offset += 3 + tlvLen

		if tlvType == 0x01 && len(tlvData) >= 10 { // Group State
			entry.Group = int(tlvData[1])<<8 | int(tlvData[2])
			entry.Priority = int(tlvData[3])

			state := tlvData[4]
			if name, ok := hsrpStateNames[state]; ok {
				entry.State = name
			} else {
				entry.State = fmt.Sprintf("Unknown(%d)", state)
			}

			entry.HelloTime = int(tlvData[5])<<8 | int(tlvData[6])
			entry.HoldTime = int(tlvData[7])<<8 | int(tlvData[8])

			if len(tlvData) >= 14 {
				entry.VirtualIP = net.IP(tlvData[10:14]).String()
			}
		}
	}

	return entry, entry.State != ""
}
