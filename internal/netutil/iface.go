package netutil

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"

	"net-finder/internal/models"
)

func GetInterface(name string) (*net.Interface, error) {
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

	return nil, fmt.Errorf("no suitable network interface found")
}

func GetInterfaceAddr(iface *net.Interface) (net.IP, net.HardwareAddr, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, nil, err
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
			return ipnet.IP.To4(), iface.HardwareAddr, nil
		}
	}

	return nil, nil, fmt.Errorf("no IPv4 address found")
}

func ParseSubnets(subnetStr string, iface *net.Interface) []*net.IPNet {
	var subnets []*net.IPNet

	if subnetStr != "" {
		parts := strings.Split(subnetStr, ",")
		for _, part := range parts {
			_, ipnet, err := net.ParseCIDR(strings.TrimSpace(part))
			if err != nil {
				fmt.Printf("invalid subnet format: %s (%v)\n", part, err)
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

func ExpandCIDR(ipnet *net.IPNet) []net.IP {
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

func GroupMACsByDevice(macs []net.HardwareAddr) [][]net.HardwareAddr {
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

// GetDefaultGateway reads the default gateway from /proc/net/route
func GetDefaultGateway() string {
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

// GetInterfaceForMode returns an interface suitable for the given IP mode.
// For IPv6 or Both, the interface must have an IPv6 address.
// For IPv4 or Both, the interface must have an IPv4 address.
func GetInterfaceForMode(name string, mode models.IPMode) (*net.Interface, error) {
	if name != "" {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			return nil, err
		}
		return iface, nil
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 || len(iface.HardwareAddr) == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		hasIPv4, hasIPv6 := false, false
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				if ipnet.IP.To4() != nil {
					hasIPv4 = true
				} else if ipnet.IP.To16() != nil {
					hasIPv6 = true
				}
			}
		}
		switch mode {
		case models.IPModeIPv4:
			if hasIPv4 {
				return &iface, nil
			}
		case models.IPModeIPv6:
			if hasIPv6 {
				return &iface, nil
			}
		default: // Both
			if hasIPv4 {
				return &iface, nil
			}
		}
	}

	return nil, fmt.Errorf("no suitable network interface found (mode: %s)", mode)
}

// GetInterfaceAddrV6 returns the global IPv6, link-local IPv6 and MAC for an interface
func GetInterfaceAddrV6(iface *net.Interface) (globalIP, linkLocalIP net.IP, mac net.HardwareAddr, err error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, nil, nil, err
	}

	mac = iface.HardwareAddr

	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipnet.IP
		if ip.To4() != nil {
			continue // skip IPv4
		}
		if ip.IsLinkLocalUnicast() {
			if linkLocalIP == nil {
				linkLocalIP = ip
			}
		} else if ip.IsGlobalUnicast() {
			if globalIP == nil {
				globalIP = ip
			}
		}
	}

	if globalIP == nil && linkLocalIP == nil {
		return nil, nil, nil, fmt.Errorf("no IPv6 address found")
	}

	return globalIP, linkLocalIP, mac, nil
}

// ParseSubnetsV6 parses IPv6 CIDR subnets from a string or from interface addresses
func ParseSubnetsV6(subnetStr string, iface *net.Interface) []*net.IPNet {
	var subnets []*net.IPNet

	if subnetStr != "" {
		parts := strings.Split(subnetStr, ",")
		for _, part := range parts {
			_, ipnet, err := net.ParseCIDR(strings.TrimSpace(part))
			if err != nil {
				continue
			}
			if ipnet.IP.To4() == nil { // only IPv6
				subnets = append(subnets, ipnet)
			}
		}
		return subnets
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return subnets
	}

	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		if ipnet.IP.To4() != nil {
			continue // skip IPv4
		}
		subnets = append(subnets, &net.IPNet{
			IP:   ipnet.IP.Mask(ipnet.Mask),
			Mask: ipnet.Mask,
		})
	}

	return subnets
}

// GetDefaultGatewayV6 reads the default IPv6 gateway from /proc/net/ipv6_route
func GetDefaultGatewayV6() string {
	f, err := os.Open("/proc/net/ipv6_route")
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}
		// fields[0]=dest, fields[1]=dest_prefix_len, fields[4]=next_hop
		dest := fields[0]
		prefixLen := fields[1]
		nextHop := fields[4]

		// Default route: destination is all zeros, prefix len is 00
		if dest == "00000000000000000000000000000000" && prefixLen == "00" && nextHop != "00000000000000000000000000000000" {
			ip := parseHexIPv6(nextHop)
			if ip != nil {
				return ip.String()
			}
		}
	}
	return ""
}

func parseHexIPv6(s string) net.IP {
	if len(s) != 32 {
		return nil
	}
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 16 {
		return nil
	}
	return net.IP(b)
}

func SortIPStrings(ips []string) {
	sort.Slice(ips, func(i, j int) bool {
		a := net.ParseIP(ips[i])
		b := net.ParseIP(ips[j])
		if a == nil || b == nil {
			return ips[i] < ips[j]
		}
		return bytes.Compare(a.To16(), b.To16()) < 0
	})
}

func SortCIDRStrings(cidrs []string) {
	sort.Slice(cidrs, func(i, j int) bool {
		_, netA, errA := net.ParseCIDR(cidrs[i])
		_, netB, errB := net.ParseCIDR(cidrs[j])
		if errA != nil || errB != nil {
			return cidrs[i] < cidrs[j]
		}
		cmp := bytes.Compare(netA.IP.To16(), netB.IP.To16())
		if cmp != 0 {
			return cmp < 0
		}
		onesA, _ := netA.Mask.Size()
		onesB, _ := netB.Mask.Size()
		return onesA < onesB
	})
}
