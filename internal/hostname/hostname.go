package hostname

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"html"
	"net"
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

// ResolveNotesStream scans all TCP ports on each IP, probes HTTP on open ports,
// and calls onResult incrementally as results are found.
// Hosts are processed one at a time to avoid semaphore contention.
func ResolveNotesStream(ips []string, stopCh <-chan struct{}, onResult func(ip, note string), onHostDone func()) {
	if len(ips) == 0 {
		return
	}

	const maxConns = 1000
	sem := make(chan struct{}, maxConns)

	for _, ip := range ips {
		select {
		case <-stopCh:
			return
		default:
		}
		note := resolveHTTP(ip, sem, stopCh)
		if note != "" {
			onResult(ip, note)
		}
		if onHostDone != nil {
			onHostDone()
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

// resolveHTTP scans all TCP ports on an IP and probes HTTP on open ports concurrently.
// Port scan and HTTP probing share the same semaphore and run in parallel —
// as soon as a port is found open, HTTP probing starts immediately.
func resolveHTTP(ip string, sem chan struct{}, stopCh <-chan struct{}) string {
	var mu sync.Mutex
	var httpResults, httpsResults []webProbeResult
	var probeWg sync.WaitGroup

	// Port scan: when a port is found open, immediately start HTTP probe
	var scanWg sync.WaitGroup
	for port := 1; port <= 65535; port++ {
		select {
		case <-stopCh:
			scanWg.Wait()
			probeWg.Wait()
			return ""
		case sem <- struct{}{}:
		}

		scanWg.Add(1)
		go func(p int) {
			defer func() { <-sem; scanWg.Done() }()
			addr := net.JoinHostPort(ip, strconv.Itoa(p))
			conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
			if err != nil {
				return
			}
			conn.Close()

			// Open port found — start HTTP probe immediately
			portStr := strconv.Itoa(p)
			probeWg.Add(1)
			go func() {
				defer probeWg.Done()
				if r := tryHTTP(ip, portStr); r != nil {
					mu.Lock()
					if r.isTLS {
						httpsResults = append(httpsResults, *r)
					} else {
						httpResults = append(httpResults, *r)
					}
					mu.Unlock()
				}
			}()
		}(port)
	}

	scanWg.Wait()
	probeWg.Wait()

	// Sort by port number
	sortResults := func(rs []webProbeResult) {
		sort.Slice(rs, func(i, j int) bool {
			pi, _ := strconv.Atoi(rs[i].port)
			pj, _ := strconv.Atoi(rs[j].port)
			return pi < pj
		})
	}
	sortResults(httpResults)
	sortResults(httpsResults)

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

// webProbeResult holds the result of probing a single port
type webProbeResult struct {
	port   string
	title  string
	isTLS  bool
}

// tryHTTP attempts an HTTP(S) request on a port, follows redirects, and returns title + TLS status.
func tryHTTP(ip, port string) *webProbeResult {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, port), 1*time.Second)
	if err != nil {
		return nil
	}

	// Try TLS first with short timeout, fall back to plain HTTP
	isTLS := false
	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	tlsConn.SetDeadline(time.Now().Add(1 * time.Second))
	if err := tlsConn.Handshake(); err == nil {
		isTLS = true
		conn = tlsConn
	} else {
		tlsConn.Close()
		conn, err = net.DialTimeout("tcp", net.JoinHostPort(ip, port), 1*time.Second)
		if err != nil {
			return nil
		}
	}

	path := "/"
	for redirect := 0; redirect < 3; redirect++ {
		body := httpGet(conn, ip, path)
		conn = nil // consumed

		if body == "" || !strings.HasPrefix(body, "HTTP/") {
			return nil
		}

		// Check for redirect
		if loc := extractRedirectLocation(body); loc != "" {
			// Same host redirect — follow it
			newPath := loc
			// Handle absolute URL: extract path only if same host
			if strings.HasPrefix(loc, "http://") || strings.HasPrefix(loc, "https://") {
				// If redirecting to HTTPS on same host, reconnect with TLS
				if strings.HasPrefix(loc, "https://") && !isTLS {
					isTLS = true
				}
				// Extract path from URL
				slashIdx := strings.Index(loc[8:], "/") // skip "https://"
				if slashIdx != -1 {
					newPath = loc[8+slashIdx:]
				} else {
					newPath = "/"
				}
			}
			path = newPath

			// Reconnect for next request
			c, err := net.DialTimeout("tcp", net.JoinHostPort(ip, port), 1*time.Second)
			if err != nil {
				return nil
			}
			if isTLS {
				tc := tls.Client(c, &tls.Config{InsecureSkipVerify: true})
				tc.SetDeadline(time.Now().Add(1 * time.Second))
				if err := tc.Handshake(); err != nil {
					c.Close()
					return nil
				}
				conn = tc
			} else {
				conn = c
			}
			continue
		}

		// Not a redirect — try to identify the service
		if name := identifyService(body, ip); name != "" {
			return &webProbeResult{port: port, title: name, isTLS: isTLS}
		}
		return nil
	}
	return nil
}

// httpGet sends a GET request on an existing connection and returns the response body.
func httpGet(conn net.Conn, host, path string) string {
	if conn == nil {
		return ""
	}
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	req := fmt.Sprintf("GET %s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n", path, host)
	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return ""
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
		return ""
	}
	return string(buf[:total])
}

// extractRedirectLocation returns the Location header value from a 3xx response, or "".
func extractRedirectLocation(response string) string {
	// Check for 3xx status
	if len(response) < 12 {
		return ""
	}
	status := response[9:12]
	if status[0] != '3' {
		return ""
	}

	headerEnd := strings.Index(response, "\r\n\r\n")
	if headerEnd == -1 {
		headerEnd = len(response)
	}
	for _, line := range strings.Split(response[:headerEnd], "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), "location:") {
			return strings.TrimSpace(line[9:])
		}
	}
	return ""
}

// identifyService extracts service identity from an HTTP response using multiple strategies:
// 1. HTML <title> tag (any status code)
// 2. X-*-Version / X-*-Build headers (auto-detected)
// 3. Server header (non-generic)
// 4. JSON body (name/version/product keys)
func identifyService(response, ip string) string {
	headerEnd := strings.Index(response, "\r\n\r\n")
	var headers, body string
	if headerEnd != -1 {
		headers = response[:headerEnd]
		body = response[headerEnd+4:]
	} else {
		headers = response
	}

	// 1. HTML <title> — try on any status code
	if title := extractTitle(body, ip); title != "" {
		return title
	}

	// 2. Auto-detect X-*-Version / X-*-Name / X-*-Build headers
	if name := extractFromXHeaders(headers); name != "" {
		return name
	}

	// 3. Server header (skip generic web servers)
	if name := extractFromServer(headers); name != "" {
		return name
	}

	// 4. JSON body
	body = strings.TrimSpace(body)
	if len(body) > 0 && body[0] == '{' {
		if name := extractFromJSON(body); name != "" {
			return name
		}
	}

	return ""
}

// extractTitle pulls <title> from HTML, filtering out useless titles.
func extractTitle(body, ip string) string {
	lower := strings.ToLower(body)
	start := strings.Index(lower, "<title>")
	if start == -1 {
		return ""
	}
	start += 7
	end := strings.Index(lower[start:], "</title>")
	if end == -1 {
		return ""
	}
	title := html.UnescapeString(strings.TrimSpace(body[start : start+end]))
	if title == "" || title == ip {
		return ""
	}
	tl := strings.ToLower(title)
	skip := []string{"document", "untitled", "welcome", "index of", "404", "not found",
		"error", "forbidden", "unauthorized", "bad request", "301 moved", "302 found",
		"page not found", "default page", "it works", "test page", "web server"}
	for _, s := range skip {
		if strings.Contains(tl, s) {
			return ""
		}
	}
	return title
}

// extractFromXHeaders auto-detects X-*-Version, X-*-Build, X-*-Name style headers.
// Extracts the service name from the header key itself.
func extractFromXHeaders(headers string) string {
	for _, line := range strings.Split(headers, "\r\n") {
		lineLower := strings.ToLower(line)
		if !strings.HasPrefix(lineLower, "x-") {
			continue
		}
		colonIdx := strings.Index(line, ":")
		if colonIdx == -1 {
			continue
		}
		key := strings.TrimSpace(line[:colonIdx])
		val := strings.TrimSpace(line[colonIdx+1:])
		keyLower := strings.ToLower(key)

		// Match X-*-Version, X-*-Build, X-*-Api-Version patterns
		isVersion := strings.HasSuffix(keyLower, "-version") ||
			strings.HasSuffix(keyLower, "-build") ||
			strings.HasSuffix(keyLower, "-api-version")
		// Match X-*-Name patterns
		isName := strings.HasSuffix(keyLower, "-name") && !strings.Contains(keyLower, "header")

		if !isVersion && !isName {
			continue
		}

		// Extract service name from header key: "X-Influxdb-Version" → "Influxdb"
		name := key[2:] // strip "X-"
		// Remove suffix
		for _, suffix := range []string{"-Version", "-version", "-Build", "-build",
			"-Api-Version", "-api-version", "-Name", "-name"} {
			if strings.HasSuffix(name, suffix) {
				name = name[:len(name)-len(suffix)]
				break
			}
		}
		name = strings.ReplaceAll(name, "-", " ")
		name = strings.TrimSpace(name)

		if name == "" {
			continue
		}
		if isVersion && val != "" {
			return fmt.Sprintf("%s %s", name, val)
		}
		if isName && val != "" {
			return val
		}
	}
	return ""
}

// extractFromServer uses the Server header if it's not a generic web server.
func extractFromServer(headers string) string {
	generic := []string{"apache", "nginx", "httpd", "lighttpd", "openresty",
		"gunicorn", "python", "gws", "cloudflare", "akamai", "microsoft-iis"}
	for _, line := range strings.Split(headers, "\r\n") {
		if !strings.HasPrefix(strings.ToLower(line), "server:") {
			continue
		}
		val := strings.TrimSpace(line[7:])
		if val == "" {
			continue
		}
		vl := strings.ToLower(val)
		isGeneric := false
		for _, g := range generic {
			if strings.Contains(vl, g) {
				isGeneric = true
				break
			}
		}
		if !isGeneric {
			return val
		}
	}
	return ""
}

// extractFromJSON identifies a service from a JSON response body.
func extractFromJSON(body string) string {
	get := func(key string) string {
		pattern := fmt.Sprintf(`"%s"`, key)
		idx := strings.Index(body, pattern)
		if idx == -1 {
			// try case-insensitive
			idx = strings.Index(strings.ToLower(body), strings.ToLower(pattern))
			if idx == -1 {
				return ""
			}
		}
		rest := body[idx+len(pattern):]
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
		end := strings.IndexAny(rest, ",}\r\n ")
		if end == -1 {
			return rest
		}
		return rest[:end]
	}

	// Try to build "name version" from common JSON key patterns
	var name, version string

	// Product/service name keys (ordered by specificity)
	for _, k := range []string{"product", "app", "application", "service",
		"name", "cluster_name", "server", "software"} {
		if v := get(k); v != "" {
			name = v
			break
		}
	}

	// Version keys
	for _, k := range []string{"version", "number", "server_version",
		"api_version", "build"} {
		if v := get(k); v != "" {
			version = v
			break
		}
	}

	if name != "" && version != "" {
		return fmt.Sprintf("%s %s", name, version)
	}
	if name != "" {
		return name
	}
	if version != "" {
		return version
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
