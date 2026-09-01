package protocol

import (
	"encoding/binary"
	"net"
	"sort"
	"sync"
	"syscall"
	"time"

	"net-finder/internal/netutil"
)

// SYN scanning: send a TCP SYN to every (host, port) and collect the SYN-ACK
// responses asynchronously, never blocking per port on a connect timeout. This
// is dramatically faster than connect() scanning for a full 1-65535 sweep across
// many hosts - send rate is the only limit, not per-port round-trips.
//
// Sends go out a SOCK_RAW socket (AF_INET or AF_INET6) so the kernel handles
// routing and L2 framing (no destination-MAC bookkeeping). Responses are captured
// on an AF_PACKET socket with a BPF filter matching only TCP segments addressed to
// our scan source port. The kernel, having no socket bound to that port, replies to
// each SYN-ACK with a RST - harmless here (we already recorded the open port, and
// the RST politely tears down the half-open connection on the target).
const (
	synScanSrcPort uint16 = 61234      // dedicated source port for scan SYNs
	synSeq         uint32 = 0x5C0FFEE5 // fixed initial sequence number
)

// SYNScanSrcPort is the port above, exported so the conntrack exemption can be
// scoped to exactly the traffic this scan produces.
const SYNScanSrcPort = synScanSrcPort

// synHostState collects the open ports discovered for a single host.
type synHostState struct {
	mu   sync.Mutex
	open map[int]bool
}

func (s *synHostState) add(port int) {
	s.mu.Lock()
	s.open[port] = true
	s.mu.Unlock()
}

// SYNScanIPv4 SYN-scans the given IPv4 hosts across the given ports and returns
// the open TCP ports per host (keyed by IP string). srcIP must be the scanning
// interface's own IPv4 address. It honours stopCh for cancellation.
func SYNScanIPv4(iface *net.Interface, srcIP net.IP, hosts []net.IP, ports []int, timeout time.Duration, stopCh <-chan struct{}) map[string][]int {
	result := make(map[string][]int)
	if srcIP == nil || srcIP.To4() == nil || len(hosts) == 0 || len(ports) == 0 {
		return result
	}

	// Receive socket: capture TCP responses addressed to our scan source port.
	recv, err := netutil.NewRawSocket(iface.Name)
	if err != nil {
		return result
	}
	defer recv.Close()
	if err := recv.SetBPFFilter(netutil.BPFFilterTCPToPort(synScanSrcPort)); err != nil {
		return result
	}

	// Send socket: raw IPv4 TCP; kernel builds the IP header and routes.
	sendFD, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return result
	}
	defer syscall.Close(sendFD)

	src4 := srcIP.To4()
	states := make(map[string]*synHostState, len(hosts))
	var v4hosts []net.IP
	for _, ip := range hosts {
		if ip4 := ip.To4(); ip4 != nil {
			states[ip.String()] = &synHostState{open: make(map[int]bool)}
			v4hosts = append(v4hosts, ip4)
		}
	}
	if len(v4hosts) == 0 {
		return result
	}

	// Reader: mark open ports until done is closed.
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
			}
			data, err := recv.ReadPacket()
			if err != nil || data == nil {
				continue
			}
			ip, port, synack := parseSYNACK(data)
			if !synack {
				continue
			}
			if st, ok := states[ip]; ok {
				st.add(port)
			}
		}
	}()

	// Give the reader a moment to attach before flooding.
	time.Sleep(50 * time.Millisecond)

	// Single send pass: one SYN per (host, port), globally rate-limited.
	var tcp [20]byte
	stopped := false
	for _, ip4 := range v4hosts {
		if stopped {
			break
		}
		var addr syscall.SockaddrInet4
		copy(addr.Addr[:], ip4)
		for _, port := range ports {
			select {
			case <-stopCh:
				stopped = true
			default:
			}
			if stopped {
				break
			}
			netutil.SYNScanAcquire()
			seg := buildSYN(src4, ip4, synScanSrcPort, uint16(port), synSeq, tcp[:])
			_ = syscall.Sendto(sendFD, seg, 0, &addr)
		}
	}

	// Wait for the last responses to arrive, then stop the reader.
	time.Sleep(timeout)
	close(done)
	wg.Wait()

	collectOpen(states, result)
	return result
}

// collectOpen moves the per-host open-port sets into the returned map, dropping
// hosts that answered on nothing.
func collectOpen(states map[string]*synHostState, result map[string][]int) {
	for ipStr, st := range states {
		st.mu.Lock()
		if len(st.open) > 0 {
			ports := make([]int, 0, len(st.open))
			for p := range st.open {
				ports = append(ports, p)
			}
			sort.Ints(ports)
			result[ipStr] = ports
		}
		st.mu.Unlock()
	}
}

// v6SendGroup is a set of targets that share one source address. A link-local
// destination has to be answered from our link-local address on this interface
// (with its zone id); anything else goes out the global address.
type v6SendGroup struct {
	src   net.IP
	zone  uint32
	hosts [][16]byte
}

// SYNScanIPv6 SYN-scans the given IPv6 hosts across the given ports and returns
// the open TCP ports per host (keyed by IP string). srcGlobal and srcLinkLocal are
// the scanning interface's own addresses; either may be nil, in which case
// destinations of that scope are skipped. It honours stopCh for cancellation.
func SYNScanIPv6(iface *net.Interface, srcGlobal, srcLinkLocal net.IP, hosts []net.IP, ports []int, timeout time.Duration, stopCh <-chan struct{}) map[string][]int {
	result := make(map[string][]int)
	if iface == nil || len(hosts) == 0 || len(ports) == 0 {
		return result
	}

	linkLocal := &v6SendGroup{src: srcLinkLocal, zone: uint32(iface.Index)}
	global := &v6SendGroup{src: srcGlobal}
	states := make(map[string]*synHostState, len(hosts))
	for _, ip := range hosts {
		ip16 := ip.To16()
		if ip16 == nil || ip.To4() != nil {
			continue
		}
		g := global
		if ip.IsLinkLocalUnicast() {
			g = linkLocal
		}
		if g.src == nil {
			continue
		}
		var addr [16]byte
		copy(addr[:], ip16)
		g.hosts = append(g.hosts, addr)
		states[ip.String()] = &synHostState{open: make(map[int]bool)}
	}
	if len(states) == 0 {
		return result
	}

	// Receive socket: capture TCP responses addressed to our scan source port.
	recv, err := netutil.NewRawSocket(iface.Name)
	if err != nil {
		return result
	}
	defer recv.Close()
	if err := recv.SetBPFFilter(netutil.BPFFilterTCP6ToPort(synScanSrcPort)); err != nil {
		return result
	}

	// Reader: mark open ports until done is closed.
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
			}
			data, err := recv.ReadPacket()
			if err != nil || data == nil {
				continue
			}
			ip, port, synack := parseSYNACK6(data)
			if !synack {
				continue
			}
			if st, ok := states[ip]; ok {
				st.add(port)
			}
		}
	}()

	// Give the reader a moment to attach before flooding.
	time.Sleep(50 * time.Millisecond)

	for _, g := range []*v6SendGroup{linkLocal, global} {
		if len(g.hosts) == 0 {
			continue
		}
		sendSYNv6(g, ports, stopCh)
	}

	// Wait for the last responses to arrive, then stop the reader.
	time.Sleep(timeout)
	close(done)
	wg.Wait()

	collectOpen(states, result)
	return result
}

// sendSYNv6 sends one SYN per (host, port) in the group, globally rate-limited.
// The socket is bound to the group's source address so the source is fixed and the
// checksum we compute is the one the target will verify.
func sendSYNv6(g *v6SendGroup, ports []int, stopCh <-chan struct{}) {
	fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return
	}
	defer syscall.Close(fd)

	bind := syscall.SockaddrInet6{ZoneId: g.zone}
	copy(bind.Addr[:], g.src.To16())
	if err := syscall.Bind(fd, &bind); err != nil {
		return
	}

	var tcp [20]byte
	for _, host := range g.hosts {
		select {
		case <-stopCh:
			return
		default:
		}
		addr := syscall.SockaddrInet6{Addr: host, ZoneId: g.zone}
		dst := net.IP(host[:])
		for _, port := range ports {
			select {
			case <-stopCh:
				return
			default:
			}
			netutil.SYNScanAcquire()
			seg := buildSYN6(g.src, dst, synScanSrcPort, uint16(port), synSeq, tcp[:])
			_ = syscall.Sendto(fd, seg, 0, &addr)
		}
	}
}

// parseSYNACK6 is parseSYNACK for IPv6. The IPv6 header is a fixed 40 bytes, so
// the TCP segment sits at a constant offset.
func parseSYNACK6(data []byte) (string, int, bool) {
	const off = 14 + 40 // Ethernet header + fixed IPv6 header
	if len(data) < off+20 {
		return "", 0, false
	}
	if data[12] != 0x86 || data[13] != 0xDD { // IPv6
		return "", 0, false
	}
	if data[20] != 6 { // Next Header: TCP
		return "", 0, false
	}
	if binary.BigEndian.Uint16(data[off+2:]) != synScanSrcPort {
		return "", 0, false
	}
	if data[off+13]&0x12 != 0x12 { // SYN+ACK
		return "", 0, false
	}
	srcPort := int(binary.BigEndian.Uint16(data[off:]))
	return net.IP(data[22:38]).String(), srcPort, true
}

// parseSYNACK extracts (srcIP, srcPort, isSYNACK) from a captured Ethernet frame,
// without allocating. isSYNACK is true only for a TCP SYN+ACK addressed to our
// scan source port (i.e. an open port reporting back).
func parseSYNACK(data []byte) (string, int, bool) {
	if len(data) < 34 { // 14 eth + 20 min IPv4
		return "", 0, false
	}
	if data[12] != 0x08 || data[13] != 0x00 { // IPv4
		return "", 0, false
	}
	if data[23] != 6 { // TCP
		return "", 0, false
	}
	ihl := int(data[14]&0x0f) * 4
	off := 14 + ihl
	if len(data) < off+14 {
		return "", 0, false
	}
	dstPort := uint16(data[off+2])<<8 | uint16(data[off+3])
	if dstPort != synScanSrcPort {
		return "", 0, false
	}
	flags := data[off+13]
	if flags&0x12 != 0x12 { // SYN+ACK
		return "", 0, false
	}
	srcPort := int(uint16(data[off])<<8 | uint16(data[off+1]))
	srcIP := net.IPv4(data[26], data[27], data[28], data[29]).String()
	return srcIP, srcPort, true
}

// buildSYN writes a 20-byte IPv4 TCP SYN header (with checksum) into buf and
// returns the filled slice. buf must be at least 20 bytes.
func buildSYN(srcIP, dstIP net.IP, srcPort, dstPort uint16, seq uint32, buf []byte) []byte {
	b := synHeader(srcPort, dstPort, seq, buf)
	binary.BigEndian.PutUint16(b[16:], tcpChecksum(srcIP.To4(), dstIP.To4(), b))
	return b
}

// buildSYN6 is buildSYN for IPv6: the same segment with an IPv6 pseudo-header
// checksum. srcIP must be the address the sending socket is bound to, or the
// checksum will not match the packet that leaves the box.
func buildSYN6(srcIP, dstIP net.IP, srcPort, dstPort uint16, seq uint32, buf []byte) []byte {
	b := synHeader(srcPort, dstPort, seq, buf)
	binary.BigEndian.PutUint16(b[16:], tcpChecksum6(srcIP, dstIP, b))
	return b
}

// synHeader fills buf with a 20-byte TCP SYN segment, checksum left zero.
func synHeader(srcPort, dstPort uint16, seq uint32, buf []byte) []byte {
	b := buf[:20]
	for i := range b {
		b[i] = 0
	}
	binary.BigEndian.PutUint16(b[0:], srcPort)
	binary.BigEndian.PutUint16(b[2:], dstPort)
	binary.BigEndian.PutUint32(b[4:], seq)
	b[12] = 5 << 4 // data offset: 5 32-bit words
	b[13] = 0x02   // SYN
	binary.BigEndian.PutUint16(b[14:], 1024) // window
	return b
}

// tcpChecksum computes the TCP checksum over the IPv4 pseudo-header plus segment.
func tcpChecksum(src, dst net.IP, tcp []byte) uint16 {
	var sum uint32
	sum += uint32(src[0])<<8 | uint32(src[1])
	sum += uint32(src[2])<<8 | uint32(src[3])
	sum += uint32(dst[0])<<8 | uint32(dst[1])
	sum += uint32(dst[2])<<8 | uint32(dst[3])
	sum += uint32(6) // protocol: TCP
	sum += uint32(len(tcp))
	return foldChecksum(sum, tcp)
}

// tcpChecksum6 computes the TCP checksum over the IPv6 pseudo-header plus segment.
// The IPv6 pseudo-header carries 128-bit addresses, a 32-bit upper-layer length and
// the next-header value, so it is not interchangeable with the IPv4 one.
func tcpChecksum6(src, dst net.IP, tcp []byte) uint16 {
	var sum uint32
	s16, d16 := src.To16(), dst.To16()
	for i := 0; i < 16; i += 2 {
		sum += uint32(s16[i])<<8 | uint32(s16[i+1])
	}
	for i := 0; i < 16; i += 2 {
		sum += uint32(d16[i])<<8 | uint32(d16[i+1])
	}
	sum += uint32(len(tcp)) // upper-layer packet length
	sum += uint32(6)        // next header: TCP
	return foldChecksum(sum, tcp)
}

// foldChecksum adds the segment to a pseudo-header sum and folds it to 16 bits.
func foldChecksum(sum uint32, tcp []byte) uint16 {
	for i := 0; i+1 < len(tcp); i += 2 {
		sum += uint32(tcp[i])<<8 | uint32(tcp[i+1])
	}
	if len(tcp)%2 == 1 {
		sum += uint32(tcp[len(tcp)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
