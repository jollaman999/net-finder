package main

import (
	"encoding/binary"
	"fmt"
	"net"
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
		fmt.Printf("경고: %s 서브넷이 너무 큽니다. /16 이하를 사용해주세요.\n", ipnet)
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
