package main

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
)

func getInterface(name string) (*net.Interface, error) {
	if name != "" {
		return net.InterfaceByName(name)
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if len(iface.HardwareAddr) == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
				return &iface, nil
			}
		}
	}

	return nil, fmt.Errorf("적합한 네트워크 인터페이스를 찾을 수 없습니다")
}

func getInterfaceAddr(iface *net.Interface) (net.IP, net.HardwareAddr, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, nil, err
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
			return ipnet.IP.To4(), iface.HardwareAddr, nil
		}
	}

	return nil, nil, fmt.Errorf("IPv4 주소를 찾을 수 없습니다")
}

func parseSubnets(subnetStr string, iface *net.Interface) []*net.IPNet {
	var subnets []*net.IPNet

	if subnetStr != "" {
		parts := strings.Split(subnetStr, ",")
		for _, part := range parts {
			_, ipnet, err := net.ParseCIDR(strings.TrimSpace(part))
			if err != nil {
				fmt.Printf("잘못된 서브넷 형식: %s (%v)\n", part, err)
				continue
			}
			subnets = append(subnets, ipnet)
		}
		return subnets
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return subnets
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
			subnets = append(subnets, &net.IPNet{
				IP:   ipnet.IP.Mask(ipnet.Mask),
				Mask: ipnet.Mask,
			})
		}
	}

	return subnets
}

func expandCIDR(ipnet *net.IPNet) []net.IP {
	ones, bits := ipnet.Mask.Size()
	hostBits := bits - ones

	if hostBits > 16 {
		return nil
	}

	numHosts := 1 << uint(hostBits)
	baseIP := ipnet.IP.To4()
	if baseIP == nil {
		return nil
	}
	base := binary.BigEndian.Uint32(baseIP)

	var ips []net.IP
	for i := 1; i < numHosts-1; i++ {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, base+uint32(i))
		ips = append(ips, ip)
	}

	return ips
}

func groupMACsByDevice(macs []net.HardwareAddr) [][]net.HardwareAddr {
	if len(macs) == 0 {
		return nil
	}

	sorted := make([]net.HardwareAddr, len(macs))
	copy(sorted, macs)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].String() < sorted[j].String()
	})

	var groups [][]net.HardwareAddr
	current := []net.HardwareAddr{sorted[0]}

	for i := 1; i < len(sorted); i++ {
		prev := current[len(current)-1]
		cur := sorted[i]

		consecutive := false
		if len(prev) == 6 && len(cur) == 6 &&
			prev[0] == cur[0] && prev[1] == cur[1] && prev[2] == cur[2] &&
			prev[3] == cur[3] && prev[4] == cur[4] {
			diff := int(cur[5]) - int(prev[5])
			consecutive = diff >= 1 && diff <= 7
		}

		if consecutive {
			current = append(current, cur)
		} else {
			groups = append(groups, current)
			current = []net.HardwareAddr{cur}
		}
	}
	groups = append(groups, current)

	return groups
}

// getDefaultGateway reads the default gateway from /proc/net/route
func getDefaultGateway() string {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Scan() // skip header
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}
		// Destination == 00000000 means default route, skip if gateway is also 00000000
		if fields[1] == "00000000" && fields[2] != "00000000" {
			gw, err := hex.DecodeString(fields[2])
			if err != nil || len(gw) != 4 {
				continue
			}
			// /proc/net/route stores in little-endian
			return fmt.Sprintf("%d.%d.%d.%d", gw[3], gw[2], gw[1], gw[0])
		}
	}
	return ""
}

func sortIPStrings(ips []string) {
	sort.Slice(ips, func(i, j int) bool {
		a := net.ParseIP(ips[i]).To4()
		b := net.ParseIP(ips[j]).To4()
		if a == nil || b == nil {
			return ips[i] < ips[j]
		}
		return binary.BigEndian.Uint32(a) < binary.BigEndian.Uint32(b)
	})
}

func sortCIDRStrings(cidrs []string) {
	sort.Slice(cidrs, func(i, j int) bool {
		_, netA, errA := net.ParseCIDR(cidrs[i])
		_, netB, errB := net.ParseCIDR(cidrs[j])
		if errA != nil || errB != nil {
			return cidrs[i] < cidrs[j]
		}
		ipA := netA.IP.To4()
		ipB := netB.IP.To4()
		if ipA == nil || ipB == nil {
			return cidrs[i] < cidrs[j]
		}
		a := binary.BigEndian.Uint32(ipA)
		b := binary.BigEndian.Uint32(ipB)
		if a != b {
			return a < b
		}
		onesA, _ := netA.Mask.Size()
		onesB, _ := netB.Mask.Size()
		return onesA < onesB
	})
}
