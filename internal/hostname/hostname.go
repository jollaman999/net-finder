package hostname

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"html"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"net-finder/internal/models"
)

// ResolveHostnames resolves hostnames for a list of IPs using multiple methods:
// 1. DNS PTR (reverse DNS)
// 2. NetBIOS Name Service (UDP 137) - Windows/Samba hosts
// 3. mDNS (UDP 5353) - Linux (Avahi) / macOS hosts
// 4. SNMP sysName (UDP 161) - network devices / servers with SNMP
// 5. TLS Certificate CN/SAN (TCP 443) - HTTPS servers, ESXi, etc.
// 6. HTTP title (TCP 443/80) - web management pages
// 7. SMTP Banner (TCP 25) - mail servers
func ResolveHostnames(ips []string) []models.HostnameEntry {
	if len(ips) == 0 {
		return nil
	}

	var mu sync.Mutex
	resolved := make(map[string]string)

	workers := 20
	if len(ips) < workers {
		workers = len(ips)
	}

	ch := make(chan string, len(ips))
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resolver := &net.Resolver{}
			for ip := range ch {
				hostname := ""

				hostname = resolveDNSPTR(resolver, ip)
				if hostname == "" {
					hostname = resolveNetBIOS(ip)
				}
				if hostname == "" {
					hostname = resolveMDNS(ip)
				}
				if hostname == "" {
					hostname = resolveSNMP(ip)
				}
				if hostname == "" {
					hostname = resolveTLS(ip)
				}
				if hostname == "" {
					hostname = resolveSMTP(ip)
				}

				if hostname != "" {
					mu.Lock()
					resolved[ip] = hostname
					mu.Unlock()
				}
			}
		}()
	}

	for _, ip := range ips {
		ch <- ip
	}
	close(ch)
	wg.Wait()

	var results []models.HostnameEntry
	for ip, hostname := range resolved {
		results = append(results, models.HostnameEntry{IP: ip, Hostname: hostname})
	}
	return results
}

// ResolveNotesStream scans all TCP ports on each IP sequentially, probes HTTP on open ports,
// and calls onResult incrementally as results are found.
// Concurrency is controlled by a semaphore limiting total simultaneous TCP connections.
func ResolveNotesStream(ips []string, stopCh <-chan struct{}, onResult func(ip, note string)) {
	if len(ips) == 0 {
		return
	}

	const maxConns = 500
	sem := make(chan struct{}, maxConns)

	for _, ip := range ips {
		select {
		case <-stopCh:
			return
		default:
		}
		if note := resolveHTTP(ip, sem, stopCh); note != "" {
			onResult(ip, note)
		}
	}
}

// resolveDNSPTR performs a reverse DNS lookup
func resolveDNSPTR(resolver *net.Resolver, ip string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	names, err := resolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}

// resolveNetBIOS sends a NetBIOS Node Status query (UDP 137)
// NetBIOS is IPv4-only; skip for IPv6 addresses.
func resolveNetBIOS(ip string) string {
	if net.ParseIP(ip).To4() == nil {
		return "" // NetBIOS is IPv4-only
	}
	conn, err := net.DialTimeout("udp4", ip+":137", 500*time.Millisecond)
	if err != nil {
		return ""
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(1 * time.Second))

	// NetBIOS Node Status Request for wildcard name "*"
	query := make([]byte, 50)
	binary.BigEndian.PutUint16(query[0:2], 0x1337)  // Transaction ID
	binary.BigEndian.PutUint16(query[2:4], 0x0000)   // Flags
	binary.BigEndian.PutUint16(query[4:6], 0x0001)   // Questions: 1
	query[12] = 0x20                                   // Name length: 32

	// Encode wildcard name "*" + 15 null bytes
	nbName := make([]byte, 16)
	nbName[0] = '*'
	for i := 0; i < 16; i++ {
		query[13+i*2] = byte('A') + (nbName[i] >> 4)
		query[14+i*2] = byte('A') + (nbName[i] & 0x0F)
	}
	query[45] = 0x00                                   // Name terminator
	binary.BigEndian.PutUint16(query[46:48], 0x0021)  // Type: NBSTAT
	binary.BigEndian.PutUint16(query[48:50], 0x0001)  // Class: IN

	if _, err = conn.Write(query); err != nil {
		return ""
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n < 57 {
		return ""
	}

	// Skip header (12 bytes) + encoded name + answer header
	pos := 12
	for pos < n {
		l := int(buf[pos])
		if l == 0 {
			pos++
			break
		}
		pos += l + 1
	}
	pos += 10 // Type(2) + Class(2) + TTL(4) + DataLen(2)

	if pos >= n {
		return ""
	}

	numNames := int(buf[pos])
	pos++

	for i := 0; i < numNames && pos+18 <= n; i++ {
		nameBytes := buf[pos : pos+15]
		nameType := buf[pos+15]
		flags := binary.BigEndian.Uint16(buf[pos+16 : pos+18])
		pos += 18

		name := strings.TrimSpace(string(nameBytes))
		// Type 0x00=Workstation, 0x20=File Server; skip group names
		if (nameType == 0x00 || nameType == 0x20) && (flags&0x8000 == 0) && name != "" {
			return name
		}
	}
	return ""
}

// resolveMDNS performs an mDNS reverse PTR lookup (UDP 5353) with unicast response
func resolveMDNS(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}

	var arpaName string
	if parsed.To4() != nil {
		p4 := parsed.To4()
		arpaName = fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", p4[3], p4[2], p4[1], p4[0])
	} else {
		arpaName = buildIPv6ArpaName(parsed)
	}
	query := buildDNSQuery(0x0000, arpaName, 12, true) // PTR=12, unicast=true

	// Send unicast query directly to the target host on port 5353
	conn, err := net.DialTimeout("udp", net.JoinHostPort(ip, "5353"), 500*time.Millisecond)
	if err != nil {
		return ""
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(1 * time.Second))

	if _, err = conn.Write(query); err != nil {
		return ""
	}

	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil || n < 12 {
		return ""
	}

	hostname := parseDNSPTRResponse(buf[:n])
	if hostname != "" {
		hostname = strings.TrimSuffix(hostname, ".")
		hostname = strings.TrimSuffix(hostname, ".local")
		return hostname
	}
	return ""
}

// resolveSNMP queries SNMP sysName (OID 1.3.6.1.2.1.1.5.0) with community "public"
func resolveSNMP(ip string) string {
	conn, err := net.DialTimeout("udp", net.JoinHostPort(ip, "161"), 500*time.Millisecond)
	if err != nil {
		return ""
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(1 * time.Second))

	// SNMPv2c GET request for sysName.0 (1.3.6.1.2.1.1.5.0)
	pkt := buildSNMPGetRequest("public", []int{1, 3, 6, 1, 2, 1, 1, 5, 0})

	if _, err = conn.Write(pkt); err != nil {
		return ""
	}

	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil || n < 20 {
		return ""
	}

	return parseSNMPResponse(buf[:n])
}

// ── DNS helpers ──

func buildDNSQuery(txID uint16, name string, qtype uint16, unicast bool) []byte {
	var pkt []byte

	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], txID)
	binary.BigEndian.PutUint16(header[4:6], 0x0001) // Questions: 1
	pkt = append(pkt, header...)

	for _, part := range strings.Split(name, ".") {
		pkt = append(pkt, byte(len(part)))
		pkt = append(pkt, []byte(part)...)
	}
	pkt = append(pkt, 0x00)

	tail := make([]byte, 4)
	binary.BigEndian.PutUint16(tail[0:2], qtype)
	qclass := uint16(0x0001)
	if unicast {
		qclass |= 0x8000 // QU bit: request unicast response
	}
	binary.BigEndian.PutUint16(tail[2:4], qclass)
	pkt = append(pkt, tail...)

	return pkt
}

func parseDNSPTRResponse(data []byte) string {
	if len(data) < 12 {
		return ""
	}
	anCount := binary.BigEndian.Uint16(data[6:8])
	if anCount == 0 {
		return ""
	}

	pos := 12
	qdCount := binary.BigEndian.Uint16(data[4:6])
	for i := 0; i < int(qdCount); i++ {
		pos = skipDNSName(data, pos)
		if pos < 0 || pos+4 > len(data) {
			return ""
		}
		pos += 4
	}

	for i := 0; i < int(anCount); i++ {
		pos = skipDNSName(data, pos)
		if pos < 0 || pos+10 > len(data) {
			return ""
		}
		rtype := binary.BigEndian.Uint16(data[pos : pos+2])
		pos += 8 // type(2) + class(2) + TTL(4)
		rdLen := binary.BigEndian.Uint16(data[pos : pos+2])
		pos += 2

		if pos+int(rdLen) > len(data) {
			return ""
		}
		if rtype == 12 { // PTR
			name := readDNSName(data, pos)
			if name != "" {
				return name
			}
		}
		pos += int(rdLen)
	}
	return ""
}

func skipDNSName(data []byte, pos int) int {
	for pos < len(data) {
		l := int(data[pos])
		if l == 0 {
			return pos + 1
		}
		if l&0xC0 == 0xC0 {
			return pos + 2
		}
		pos += l + 1
	}
	return -1
}

func readDNSName(data []byte, pos int) string {
	var parts []string
	visited := 0
	for pos < len(data) && visited < 100 {
		visited++
		l := int(data[pos])
		if l == 0 {
			break
		}
		if l&0xC0 == 0xC0 {
			if pos+1 >= len(data) {
				break
			}
			ptr := int(binary.BigEndian.Uint16(data[pos:pos+2])) & 0x3FFF
			pos = ptr
			continue
		}
		pos++
		if pos+l > len(data) {
			break
		}
		parts = append(parts, string(data[pos:pos+l]))
		pos += l
	}
	return strings.Join(parts, ".")
}

// ── SNMP helpers ──

func buildSNMPGetRequest(community string, oid []int) []byte {
	// Encode OID
	oidBytes := encodeOID(oid)
	// VarBind: SEQUENCE { OID, NULL }
	varbind := asn1Sequence(append(asn1OID(oidBytes), asn1Null()...))
	// VarBindList: SEQUENCE { varbind }
	varbindList := asn1Sequence(varbind)
	// PDU: GetRequest (0xA0) { requestID, errorStatus, errorIndex, varbindList }
	reqID := asn1Integer(1)
	errStatus := asn1Integer(0)
	errIndex := asn1Integer(0)
	pduContent := append(reqID, errStatus...)
	pduContent = append(pduContent, errIndex...)
	pduContent = append(pduContent, varbindList...)
	pdu := asn1Constructed(0xA0, pduContent)
	// Message: SEQUENCE { version, community, pdu }
	version := asn1Integer(1) // SNMPv2c
	comm := asn1OctetString([]byte(community))
	msgContent := append(version, comm...)
	msgContent = append(msgContent, pdu...)
	return asn1Sequence(msgContent)
}

func parseSNMPResponse(data []byte) string {
	// Quick parse: find the OctetString value for sysName in the response
	// Walk through ASN.1 structure looking for the value
	pos := 0
	if pos >= len(data) || data[pos] != 0x30 {
		return "" // not a SEQUENCE
	}
	// Skip outer SEQUENCE
	_, pos = asn1ReadLength(data, pos+1)
	if pos < 0 {
		return ""
	}
	// Skip version (INTEGER)
	pos = asn1Skip(data, pos)
	// Skip community (OCTET STRING)
	pos = asn1Skip(data, pos)
	if pos < 0 || pos >= len(data) {
		return ""
	}
	// PDU (0xA2 = GetResponse)
	if data[pos] != 0xA2 {
		return ""
	}
	_, pos = asn1ReadLength(data, pos+1)
	// Skip requestID, errorStatus, errorIndex
	pos = asn1Skip(data, pos) // requestID
	pos = asn1Skip(data, pos) // errorStatus
	pos = asn1Skip(data, pos) // errorIndex
	if pos < 0 || pos >= len(data) {
		return ""
	}
	// VarBindList (SEQUENCE)
	if data[pos] != 0x30 {
		return ""
	}
	_, pos = asn1ReadLength(data, pos+1)
	// First VarBind (SEQUENCE)
	if pos >= len(data) || data[pos] != 0x30 {
		return ""
	}
	_, pos = asn1ReadLength(data, pos+1)
	// Skip OID
	pos = asn1Skip(data, pos)
	if pos < 0 || pos >= len(data) {
		return ""
	}
	// Value - should be OCTET STRING (0x04)
	if data[pos] == 0x04 {
		vlen, vpos := asn1ReadLength(data, pos+1)
		if vpos >= 0 && vpos+vlen <= len(data) {
			name := strings.TrimSpace(string(data[vpos : vpos+vlen]))
			if name != "" {
				return name
			}
		}
	}
	return ""
}

func encodeOID(oid []int) []byte {
	if len(oid) < 2 {
		return nil
	}
	result := []byte{byte(oid[0]*40 + oid[1])}
	for i := 2; i < len(oid); i++ {
		result = append(result, encodeOIDComponent(oid[i])...)
	}
	return result
}

func encodeOIDComponent(v int) []byte {
	if v < 128 {
		return []byte{byte(v)}
	}
	var parts []byte
	for v > 0 {
		parts = append([]byte{byte(v & 0x7F)}, parts...)
		v >>= 7
	}
	for i := 0; i < len(parts)-1; i++ {
		parts[i] |= 0x80
	}
	return parts
}

func asn1Sequence(content []byte) []byte {
	hdr := append([]byte{0x30}, asn1Length(len(content))...)
	return append(hdr, content...)
}

func asn1Constructed(tag byte, content []byte) []byte {
	return append(append([]byte{tag}, asn1Length(len(content))...), content...)
}

func asn1Integer(v int) []byte {
	var val []byte
	if v == 0 {
		val = []byte{0}
	} else {
		tmp := v
		for tmp > 0 {
			val = append([]byte{byte(tmp & 0xFF)}, val...)
			tmp >>= 8
		}
		if val[0]&0x80 != 0 {
			val = append([]byte{0}, val...)
		}
	}
	return append(append([]byte{0x02}, asn1Length(len(val))...), val...)
}

func asn1OctetString(v []byte) []byte {
	return append(append([]byte{0x04}, asn1Length(len(v))...), v...)
}

func asn1OID(encoded []byte) []byte {
	return append(append([]byte{0x06}, asn1Length(len(encoded))...), encoded...)
}

func asn1Null() []byte {
	return []byte{0x05, 0x00}
}

func asn1Length(l int) []byte {
	if l < 128 {
		return []byte{byte(l)}
	}
	var parts []byte
	tmp := l
	for tmp > 0 {
		parts = append([]byte{byte(tmp & 0xFF)}, parts...)
		tmp >>= 8
	}
	return append([]byte{byte(0x80 | len(parts))}, parts...)
}

func asn1ReadLength(data []byte, pos int) (int, int) {
	if pos >= len(data) {
		return 0, -1
	}
	if data[pos] < 128 {
		return int(data[pos]), pos + 1
	}
	numBytes := int(data[pos] & 0x7F)
	pos++
	length := 0
	for i := 0; i < numBytes && pos < len(data); i++ {
		length = (length << 8) | int(data[pos])
		pos++
	}
	return length, pos
}

func asn1Skip(data []byte, pos int) int {
	if pos < 0 || pos >= len(data) {
		return -1
	}
	pos++ // skip tag
	vlen, vpos := asn1ReadLength(data, pos)
	if vpos < 0 {
		return -1
	}
	return vpos + vlen
}

// resolveTLS connects to port 443 and extracts hostname from TLS certificate CN/SAN
func resolveTLS(ip string) string {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "443"), 500*time.Millisecond)
	if err != nil {
		return ""
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true,
	})
	tlsConn.SetDeadline(time.Now().Add(2 * time.Second))

	if err := tlsConn.Handshake(); err != nil {
		return ""
	}

	certs := tlsConn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return ""
	}

	cert := certs[0]

	// Try SAN DNS names first (more specific)
	for _, name := range cert.DNSNames {
		name = strings.TrimSpace(name)
		if name != "" && name != ip && !strings.HasPrefix(name, "*") {
			return name
		}
	}

	// Fall back to CN
	cn := strings.TrimSpace(cert.Subject.CommonName)
	if cn != "" && cn != ip && !strings.HasPrefix(cn, "*") {
		return cn
	}

	return ""
}

// resolveSMTP connects to port 25 and extracts hostname from SMTP banner
func resolveSMTP(ip string) string {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "25"), 500*time.Millisecond)
	if err != nil {
		return ""
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return ""
	}

	line = strings.TrimSpace(line)
	// SMTP banner format: "220 hostname ..." or "220-hostname ..."
	if !strings.HasPrefix(line, "220") {
		return ""
	}

	// Remove "220" prefix and separator
	banner := line[3:]
	if len(banner) > 0 && (banner[0] == ' ' || banner[0] == '-') {
		banner = banner[1:]
	}

	// First word is the hostname
	fields := strings.Fields(banner)
	if len(fields) == 0 {
		return ""
	}

	hostname := fields[0]
	// Validate it looks like a hostname (contains a dot or is a simple name)
	if hostname == "" || hostname == ip || hostname == "localhost" {
		return ""
	}

	return hostname
}

// resolveHTTP scans all TCP ports on an IP, then probes HTTP on open ports.
// sem limits total concurrent connections. Returns "title (:port)" or empty string.
func resolveHTTP(ip string, sem chan struct{}, stopCh <-chan struct{}) string {
	// Phase 1: full port scan with batched concurrency
	openPorts := scanWebPorts(ip, sem, stopCh)
	if len(openPorts) == 0 {
		return ""
	}

	// Phase 2: probe HTTP on all open ports, collect results
	var httpResults, httpsResults []webProbeResult
	for _, port := range openPorts {
		select {
		case <-stopCh:
			return ""
		default:
		}
		if r := tryHTTP(ip, port); r != nil {
			if r.isTLS {
				httpsResults = append(httpsResults, *r)
			} else {
				httpResults = append(httpResults, *r)
			}
		}
	}

	// Format: "HTTP name (port), name (port)\nHTTPS name (port), name (port)"
	var lines []string
	if len(httpResults) > 0 {
		var items []string
		for _, r := range httpResults {
			items = append(items, fmt.Sprintf("%s (%s)", r.title, r.port))
		}
		lines = append(lines, "HTTP\t"+strings.Join(items, ", "))
	}
	if len(httpsResults) > 0 {
		var items []string
		for _, r := range httpsResults {
			items = append(items, fmt.Sprintf("%s (%s)", r.title, r.port))
		}
		lines = append(lines, "HTTPS\t"+strings.Join(items, ", "))
	}
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n")
}

// Default web service ports to probe
var defaultWebPorts = []int{
	80, 443, 8080, 8443, 8000, 8888, 8006, 8008, 8081, 8082,
	3000, 5000, 5601, 7443, 7080, 9090, 9443, 9200, 9000,
	8086, 8087, 8161, 8181, 8280, 8880, 9999, 10000, 10443,
	2082, 2083, 2086, 2087, 4443, 4848, 6080,
	8834, 9080, 18080, 18443,
	2375, 2376, 4194, 5984, 8200, 8500, 8300,
	15672, 2379, 6443, 9093, 9100,
}

// webPorts is the active port list (overridden by config file)
var webPorts = defaultWebPorts

// LoadWebPorts loads custom web ports from ~/.config/net-finder/webports.conf.
// File format: one port per line, # for comments, empty lines ignored.
// If the file doesn't exist, default ports are used.
func LoadWebPorts() {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	path := filepath.Join(home, ".config", "net-finder", "webports.conf")
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	var ports []int
	seen := make(map[int]bool)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p, err := strconv.Atoi(line)
		if err != nil || p < 1 || p > 65535 {
			continue
		}
		if !seen[p] {
			seen[p] = true
			ports = append(ports, p)
		}
	}
	if len(ports) > 0 {
		webPorts = ports
		log.Printf("Loaded %d custom web ports from %s", len(ports), path)
	}
}

// scanWebPorts scans common web ports and returns open ones as strings.
func scanWebPorts(ip string, sem chan struct{}, stopCh <-chan struct{}) []string {
	type result struct {
		port int
	}

	results := make(chan result, len(webPorts))
	var wg sync.WaitGroup

	for _, port := range webPorts {
		select {
		case <-stopCh:
			wg.Wait()
			return nil
		case sem <- struct{}{}:
		}

		wg.Add(1)
		go func(p int) {
			defer func() { <-sem; wg.Done() }()
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, p), 3*time.Second)
			if err != nil {
				return
			}
			conn.Close()
			results <- result{p}
		}(port)
	}

	wg.Wait()
	close(results)

	var ports []int
	for r := range results {
		ports = append(ports, r.port)
	}

	sort.Ints(ports)
	out := make([]string, len(ports))
	for i, p := range ports {
		out[i] = fmt.Sprintf("%d", p)
	}
	return out
}

// webProbeResult holds the result of probing a single port
type webProbeResult struct {
	port   string
	title  string
	isTLS  bool
}

// tryHTTP attempts an HTTP(S) request on a port and returns title + TLS status.
func tryHTTP(ip, port string) *webProbeResult {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, port), 3*time.Second)
	if err != nil {
		return nil
	}

	// Try TLS first, fall back to plain HTTP
	isTLS := false
	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	tlsConn.SetDeadline(time.Now().Add(3 * time.Second))
	if err := tlsConn.Handshake(); err == nil {
		isTLS = true
		conn = tlsConn
	} else {
		tlsConn.Close()
		// Reconnect for plain HTTP
		conn, err = net.DialTimeout("tcp", net.JoinHostPort(ip, port), 3*time.Second)
		if err != nil {
			return nil
		}
	}

	conn.SetDeadline(time.Now().Add(3 * time.Second))
	req := fmt.Sprintf("GET / HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n", ip)
	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil
	}

	buf := make([]byte, 8192)
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			break
		}
	}
	conn.Close()

	if total == 0 {
		return nil
	}
	body := string(buf[:total])

	// Must be an HTTP response
	if !strings.HasPrefix(body, "HTTP/") {
		return nil
	}

	// Try to extract <title>...</title> from 200 OK responses
	if strings.Contains(body, " 200 ") {
		lower := strings.ToLower(body)
		start := strings.Index(lower, "<title>")
		if start != -1 {
			start += 7
			end := strings.Index(lower[start:], "</title>")
			if end != -1 {
				title := html.UnescapeString(strings.TrimSpace(body[start : start+end]))
				if title != "" && title != ip {
					tl := strings.ToLower(title)
					if tl != "document" && tl != "untitled" && !strings.Contains(tl, "welcome") && !strings.Contains(tl, "index of") {
						return &webProbeResult{port: port, title: title, isTLS: isTLS}
					}
				}
			}
		}
	}

	// Fallback: identify service from HTTP headers
	if name := identifyService(body); name != "" {
		return &webProbeResult{port: port, title: name, isTLS: isTLS}
	}
	return nil
}

// identifyService extracts service name from HTTP response headers and body.
func identifyService(response string) string {
	// Split headers from body
	headerEnd := strings.Index(response, "\r\n\r\n")
	var headers, body string
	if headerEnd != -1 {
		headers = response[:headerEnd]
		body = response[headerEnd+4:]
	} else {
		headers = response
	}
	headersLower := strings.ToLower(headers)

	// Known header patterns → service name
	knownHeaders := []struct {
		header string // lowercase
		prefix string
	}{
		{"x-influxdb-version:", "InfluxDB"},
		{"x-jenkins:", "Jenkins"},
		{"x-grafana-version:", "Grafana"},
		{"x-elastic-product:", ""},
		{"kbn-name:", ""},
		{"x-consul-index:", "Consul"},
		{"x-vault-token:", "Vault"},
		{"x-couchdb-body-time:", "CouchDB"},
		{"x-proxmox-api-version:", "Proxmox"},
		{"x-gitlab-meta:", "GitLab"},
		{"x-gitea-version:", "Gitea"},
		{"x-harbor-csrf-token:", "Harbor"},
		{"x-rancher-version:", "Rancher"},
		{"x-portainer-version:", "Portainer"},
		{"x-sonarqube-version:", "SonarQube"},
		{"x-redmine-api-version:", "Redmine"},
		{"x-nexus-ui:", "Nexus"},
		{"x-zabbix-version:", "Zabbix"},
	}
	for _, kh := range knownHeaders {
		idx := strings.Index(headersLower, kh.header)
		if idx == -1 {
			continue
		}
		line := headers[idx:]
		if nl := strings.IndexAny(line, "\r\n"); nl != -1 {
			line = line[:nl]
		}
		val := strings.TrimSpace(line[len(kh.header):])
		if kh.prefix != "" {
			if val != "" {
				return fmt.Sprintf("%s %s", kh.prefix, val)
			}
			return kh.prefix
		}
		if val != "" {
			return val
		}
	}

	// Server header — use for non-generic servers
	genericServers := []string{"apache", "nginx", "httpd", "lighttpd", "openresty", "gunicorn", "python"}
	for _, line := range strings.Split(headers, "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), "server:") {
			val := strings.TrimSpace(line[7:])
			if val == "" {
				continue
			}
			vl := strings.ToLower(val)
			isGeneric := false
			for _, g := range genericServers {
				if strings.Contains(vl, g) {
					isGeneric = true
					break
				}
			}
			if !isGeneric {
				return val
			}
		}
	}

	// JSON body detection for REST API services
	body = strings.TrimSpace(body)
	if len(body) > 0 && body[0] == '{' {
		return identifyFromJSON(body)
	}

	return ""
}

// identifyFromJSON tries to identify a service from a JSON response body.
func identifyFromJSON(body string) string {
	// Quick key extraction without full JSON parsing
	get := func(key string) string {
		pattern := fmt.Sprintf(`"%s"`, key)
		idx := strings.Index(body, pattern)
		if idx == -1 {
			return ""
		}
		rest := body[idx+len(pattern):]
		// skip :" or : "
		rest = strings.TrimLeft(rest, ": \t")
		if len(rest) == 0 {
			return ""
		}
		if rest[0] == '"' {
			end := strings.Index(rest[1:], `"`)
			if end == -1 {
				return ""
			}
			return rest[1 : end+1]
		}
		// numeric or boolean value
		end := strings.IndexAny(rest, ",}\r\n ")
		if end == -1 {
			return rest
		}
		return rest[:end]
	}

	// Elasticsearch: {"name":"...","cluster_name":"...","version":{"number":"..."}}
	if cn := get("cluster_name"); cn != "" {
		if ver := get("number"); ver != "" {
			return fmt.Sprintf("Elasticsearch %s (%s)", ver, cn)
		}
		return fmt.Sprintf("Elasticsearch (%s)", cn)
	}

	// CouchDB: {"couchdb":"Welcome","version":"..."}
	if get("couchdb") != "" {
		if ver := get("version"); ver != "" {
			return fmt.Sprintf("CouchDB %s", ver)
		}
		return "CouchDB"
	}

	// Consul: {"consul_version":"..."}
	if ver := get("consul_version"); ver != "" {
		return fmt.Sprintf("Consul %s", ver)
	}

	// Docker Registry: {"repositories":[...]} — from /v2/_catalog
	// Docker daemon: {"ApiVersion":"...","Version":"..."}
	if ver := get("ApiVersion"); ver != "" {
		if dv := get("Version"); dv != "" {
			return fmt.Sprintf("Docker %s", dv)
		}
	}

	// Prometheus: {"status":"...","data":{"version":"..."}}
	if get("status") == "success" {
		if ver := get("version"); ver != "" {
			return fmt.Sprintf("Prometheus %s", ver)
		}
	}

	// Minio: {"status":"..."}  — already caught by Server header usually
	// RabbitMQ management: {"rabbitmq_version":"..."}
	if ver := get("rabbitmq_version"); ver != "" {
		return fmt.Sprintf("RabbitMQ %s", ver)
	}

	// etcd: {"etcdserver":"...","etcdcluster":"..."}
	if ver := get("etcdserver"); ver != "" {
		return fmt.Sprintf("etcd %s", ver)
	}

	return ""
}

// buildIPv6ArpaName converts an IPv6 address to its ip6.arpa reverse DNS name.
func buildIPv6ArpaName(ip net.IP) string {
	ip = ip.To16()
	if ip == nil {
		return ""
	}
	// Expand to 32 hex nibbles and reverse
	hex := fmt.Sprintf("%032x", []byte(ip))
	var parts []string
	for i := len(hex) - 1; i >= 0; i-- {
		parts = append(parts, string(hex[i]))
	}
	return strings.Join(parts, ".") + ".ip6.arpa"
}
