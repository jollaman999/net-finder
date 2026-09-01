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
	"net-finder/internal/netutil"
)

// topPorts is a curated list of the most commonly used TCP ports. It is scanned
// first so a host's services show up almost immediately; the remaining ports are
// swept afterwards to catch anything unusual. Covers web, remote admin, mail,
// databases, message brokers, and common app/dev-tool ports.
var topPorts = []int{
	21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 139, 143, 161, 389, 443, 445,
	465, 514, 515, 548, 587, 623, 631, 636, 873, 990, 993, 995, 1025, 1080, 1194,
	1433, 1521, 1723, 1883, 2049, 2082, 2083, 2086, 2087, 2095, 2096, 2181, 2222,
	2375, 2376, 3000, 3128, 3268, 3306, 3389, 3690, 4000, 4040, 4443, 4444, 4567,
	4848, 5000, 5001, 5044, 5060, 5432, 5433, 5601, 5672, 5900, 5901, 5984, 6000,
	6379, 6380, 6443, 6600, 6666, 6667, 7000, 7001, 7070, 7077, 7443, 7474, 7687,
	8000, 8006, 8008, 8009, 8010, 8060, 8080, 8081, 8082, 8083, 8086, 8088, 8090,
	8091, 8096, 8123, 8161, 8180, 8200, 8222, 8291, 8333, 8443, 8500, 8530, 8531,
	8545, 8686, 8765, 8787, 8800, 8834, 8880, 8888, 8983, 9000, 9001, 9042, 9043,
	9090, 9091, 9092, 9100, 9200, 9300, 9418, 9443, 9600, 9990, 9999, 10000,
	10250, 11211, 15672, 16379, 27017, 27018, 28017, 32400, 50000, 50070, 55672,
}

// remainingPorts is every TCP port not in topPorts, swept in the second pass.
var remainingPorts []int

func init() {
	inTop := make(map[int]bool, len(topPorts))
	for _, p := range topPorts {
		inTop[p] = true
	}
	for p := 1; p <= 65535; p++ {
		if !inTop[p] {
			remainingPorts = append(remainingPorts, p)
		}
	}
}

// scanZone is the interface a link-local IPv6 address has to be qualified with
// before the kernel will route a connection to it. Set once at startup.
var scanZone string

// SetScanZone records the scanning interface's name for link-local IPv6 dialling.
func SetScanZone(iface string) { scanZone = iface }

// dialTarget builds the address to dial for a scanned host. A link-local IPv6
// address needs its interface appended ("fe80::1%eth0"); connecting without one
// fails with EINVAL, so the SYN scan would find open ports that nothing could
// then probe for a service.
func dialTarget(ip, port string) string {
	if scanZone != "" && !strings.Contains(ip, "%") {
		if parsed := net.ParseIP(ip); parsed != nil && parsed.To4() == nil && parsed.IsLinkLocalUnicast() {
			return net.JoinHostPort(ip+"%"+scanZone, port)
		}
	}
	return net.JoinHostPort(ip, port)
}

// ResolveHostnames resolves hostnames for a list of IPs using multiple methods:
// 1. DNS PTR (reverse DNS)
// 2. NetBIOS Name Service (UDP 137) - Windows/Samba hosts
// 3. mDNS (UDP 5353) - Linux (Avahi) / macOS hosts
// 4. TLS Certificate CN/SAN (TCP 443) - HTTPS servers, ESXi, etc.
// 5. SMTP Banner (TCP 25) - mail servers
//
// Network infrastructure (switches/routers/APs) is named from LLDP SysName /
// CDP DeviceID collected passively by the scanner — see scanner.resolveHostnames
// — which replaces the old, noisy SNMP "public" probing.
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

// ResolveNotesStream scans TCP ports on each IP and probes open ports for
// HTTP/HTTPS and database services, calling onResult incrementally.
//
// Scanning runs in two rounds across the whole host set rather than fully
// finishing one host before the next: first the curated topPorts on every host
// (so common services surface quickly for all hosts), then the second-pass ports
// on every host. This stops late hosts from waiting hours behind the slower sweep
// of earlier ones. All connections share the global port-scan rate limiter.
func ResolveNotesStream(ips []string, stopCh <-chan struct{}, onResult func(ip, note string), onHostDone func()) {
	if len(ips) == 0 {
		return
	}

	const maxConns = 1000
	sem := make(chan struct{}, maxConns)

	svc := make(map[string]*hostServices, len(ips))
	for _, ip := range ips {
		svc[ip] = &hostServices{probed: make(map[int]bool)}
	}

	stopped := func() bool {
		select {
		case <-stopCh:
			return true
		default:
			return false
		}
	}

	// Round 1: common ports on every host - fast, surfaces services for all.
	for _, ip := range ips {
		if stopped() {
			return
		}
		scanAndProbe(ip, topPorts, svc[ip], sem, stopCh)
		if note := svc[ip].note(); note != "" {
			onResult(ip, note)
		}
	}

	// Round 2: the remaining ports on every host.
	for _, ip := range ips {
		if stopped() {
			return
		}
		scanAndProbe(ip, remainingPorts, svc[ip], sem, stopCh)
		if note := svc[ip].note(); note != "" {
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
	binary.BigEndian.PutUint16(query[0:2], 0x1337) // Transaction ID
	binary.BigEndian.PutUint16(query[2:4], 0x0000) // Flags
	binary.BigEndian.PutUint16(query[4:6], 0x0001) // Questions: 1
	query[12] = 0x20                               // Name length: 32

	// Encode wildcard name "*" + 15 null bytes
	nbName := make([]byte, 16)
	nbName[0] = '*'
	for i := 0; i < 16; i++ {
		query[13+i*2] = byte('A') + (nbName[i] >> 4)
		query[14+i*2] = byte('A') + (nbName[i] & 0x0F)
	}
	query[45] = 0x00                                 // Name terminator
	binary.BigEndian.PutUint16(query[46:48], 0x0021) // Type: NBSTAT
	binary.BigEndian.PutUint16(query[48:50], 0x0001) // Class: IN

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
	conn, err := net.DialTimeout("udp", dialTarget(ip, "5353"), 500*time.Millisecond)
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

// resolveTLS connects to port 443 and extracts hostname from TLS certificate CN/SAN
func resolveTLS(ip string) string {
	conn, err := net.DialTimeout("tcp", dialTarget(ip, "443"), 500*time.Millisecond)
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
	conn, err := net.DialTimeout("tcp", dialTarget(ip, "25"), 500*time.Millisecond)
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

// hostServices accumulates detected services for one host across scan passes.
type hostServices struct {
	http, https []webProbeResult
	db          []dbProbeResult
	probed      map[int]bool
}

func (hs *hostServices) note() string {
	return buildServiceNote(hs.http, hs.https, hs.db)
}

// ProbeServices identifies HTTP/HTTPS and database services on a host's already
// discovered open ports (e.g. from a SYN scan) and returns the formatted note,
// or "" if none are found. No port scanning is done here - only service probing.
func ProbeServices(ip string, openPorts []int, stopCh <-chan struct{}) string {
	if len(openPorts) == 0 {
		return ""
	}
	hs := &hostServices{probed: make(map[int]bool)}
	sort.Ints(openPorts)
	for _, p := range openPorts {
		select {
		case <-stopCh:
			return hs.note()
		default:
		}
		if hs.probed[p] {
			continue
		}
		hs.probed[p] = true
		ps := strconv.Itoa(p)
		if r := tryHTTP(ip, ps); r != nil {
			if r.isTLS {
				hs.https = append(hs.https, *r)
			} else {
				hs.http = append(hs.http, *r)
			}
			continue
		}
		if d := tryDB(ip, ps); d != nil {
			hs.db = append(hs.db, *d)
		}
	}
	return hs.note()
}

// scanAndProbe scans the given ports on ip and classifies each newly-open port as
// HTTP, HTTPS, or a database service, merging the results into hs.
func scanAndProbe(ip string, ports []int, hs *hostServices, sem chan struct{}, stopCh <-chan struct{}) {
	for _, p := range scanPorts(ip, ports, sem, stopCh) {
		select {
		case <-stopCh:
			return
		default:
		}
		if hs.probed[p] {
			continue
		}
		hs.probed[p] = true
		ps := strconv.Itoa(p)
		if r := tryHTTP(ip, ps); r != nil {
			if r.isTLS {
				hs.https = append(hs.https, *r)
			} else {
				hs.http = append(hs.http, *r)
			}
			continue
		}
		if d := tryDB(ip, ps); d != nil {
			hs.db = append(hs.db, *d)
		}
	}
}

// scanPorts TCP-connect scans the given ports on an IP and returns the open ones,
// sorted ascending. Each connection is bounded by the shared semaphore and the
// global port-scan rate limiter.
func scanPorts(ip string, ports []int, sem chan struct{}, stopCh <-chan struct{}) []int {
	results := make(chan int, 256)
	var scanWg sync.WaitGroup

	go func() {
		for _, port := range ports {
			select {
			case <-stopCh:
				scanWg.Wait()
				close(results)
				return
			case sem <- struct{}{}:
			}
			scanWg.Add(1)
			go func(p int) {
				defer func() { <-sem; scanWg.Done() }()
				netutil.PortScanAcquire()
				start := time.Now()
				conn, err := net.DialTimeout("tcp", dialTarget(ip, strconv.Itoa(p)), 200*time.Millisecond)
				elapsed := time.Since(start)
				if err == nil {
					conn.Close()
					netutil.PortScanObserve(elapsed, true)
					results <- p
					return
				}
				// A refusal means the host answered (fast RTT signal); a timeout
				// means no response (usually a filtered port) — not a delay signal.
				netutil.PortScanObserve(elapsed, strings.Contains(err.Error(), "refused"))
			}(port)
		}
		scanWg.Wait()
		close(results)
	}()

	var open []int
	for p := range results {
		open = append(open, p)
	}
	sort.Ints(open)
	return open
}

// buildServiceNote formats detected HTTP/HTTPS/DB services into the host note.
// Returns "" when nothing was detected.
func buildServiceNote(httpResults, httpsResults []webProbeResult, dbResults []dbProbeResult) string {
	sortResults := func(rs []webProbeResult) {
		sort.Slice(rs, func(i, j int) bool {
			pi, _ := strconv.Atoi(rs[i].port)
			pj, _ := strconv.Atoi(rs[j].port)
			return pi < pj
		})
	}
	sortResults(httpResults)
	sortResults(httpsResults)
	sort.Slice(dbResults, func(i, j int) bool {
		pi, _ := strconv.Atoi(dbResults[i].port)
		pj, _ := strconv.Atoi(dbResults[j].port)
		return pi < pj
	})

	// Format: "HTTP name (port), ...\nHTTPS ...\nDB ..."
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
	if len(dbResults) > 0 {
		var items []string
		for _, d := range dbResults {
			items = append(items, fmt.Sprintf("%s (%s)", d.name, d.port))
		}
		lines = append(lines, "DB\t"+strings.Join(items, ", "))
	}
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n")
}

// webProbeResult holds the result of probing a single port
type webProbeResult struct {
	port  string
	title string
	isTLS bool
}

// dbProbeResult holds a detected database service on a port.
type dbProbeResult struct {
	port string
	name string
}

// dbActiveProbePorts maps well-known DB ports to their probe protocol. Active
// probes only run on these ports to keep the scan fast and avoid false
// positives. MySQL/MariaDB are detected passively (banner) on any port.
var dbActiveProbePorts = map[int]string{
	5432:  "postgres",
	5433:  "postgres",
	6379:  "redis",
	6380:  "redis",
	11211: "memcached",
	27017: "mongodb",
	27018: "mongodb",
	27019: "mongodb",
	1433:  "mssql",
	1434:  "mssql",
	1521:  "oracle",
	1522:  "oracle",
	1526:  "oracle",
}

// tryDB probes a single open port for a well-known database service. It first
// reads any server-sent banner (catches MySQL/MariaDB on any port), then, for
// standard DB ports, sends a protocol-specific probe.
func tryDB(ip, port string) *dbProbeResult {
	if name := probeMySQLBanner(ip, port); name != "" {
		return &dbProbeResult{port: port, name: name}
	}

	pnum, _ := strconv.Atoi(port)
	var name string
	switch dbActiveProbePorts[pnum] {
	case "postgres":
		name = probePostgres(ip, port)
	case "redis":
		name = probeRedis(ip, port)
	case "memcached":
		name = probeMemcached(ip, port)
	case "mongodb":
		name = probeMongoDB(ip, port)
	case "mssql":
		name = probeMSSQL(ip, port)
	case "oracle":
		name = probeOracle(ip, port)
	}
	if name != "" {
		return &dbProbeResult{port: port, name: name}
	}
	return nil
}

// probeMySQLBanner reads the MySQL/MariaDB initial handshake (sent by the server
// immediately on connect) and extracts the server version.
func probeMySQLBanner(ip, port string) string {
	conn, err := net.DialTimeout("tcp", dialTarget(ip, port), 1*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(800 * time.Millisecond))
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 6 {
		return ""
	}
	// Packet: [3-byte length][seq=0][protocol version=10][server version cstring]
	if buf[3] != 0x00 || buf[4] != 0x0a {
		return ""
	}
	seg := string(buf[5:n])
	end := strings.IndexByte(seg, 0)
	if end <= 0 {
		return ""
	}
	ver := seg[:end]
	if !isPrintableASCII(ver) {
		return ""
	}
	if strings.Contains(strings.ToLower(ver), "mariadb") {
		return "MariaDB " + ver
	}
	return "MySQL " + ver
}

// probePostgres sends an SSLRequest; PostgreSQL replies with a single 'S'/'N'.
func probePostgres(ip, port string) string {
	conn, err := net.DialTimeout("tcp", dialTarget(ip, port), 1*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()
	// SSLRequest message: int32 length=8, int32 code=80877103.
	req := make([]byte, 8)
	binary.BigEndian.PutUint32(req[0:4], 8)
	binary.BigEndian.PutUint32(req[4:8], 80877103)
	conn.SetDeadline(time.Now().Add(1 * time.Second))
	if _, err := conn.Write(req); err != nil {
		return ""
	}
	resp := make([]byte, 1)
	if _, err := conn.Read(resp); err != nil {
		return ""
	}
	if resp[0] == 'S' || resp[0] == 'N' {
		return "PostgreSQL"
	}
	return ""
}

// probeRedis sends PING; Redis replies +PONG or a -NOAUTH/-DENIED error. When
// unauthenticated it additionally fetches the version via INFO.
func probeRedis(ip, port string) string {
	conn, err := net.DialTimeout("tcp", dialTarget(ip, port), 1*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(1 * time.Second))
	if _, err := conn.Write([]byte("PING\r\n")); err != nil {
		return ""
	}
	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return ""
	}
	resp := string(buf[:n])
	if !strings.HasPrefix(resp, "+PONG") && !strings.Contains(resp, "NOAUTH") &&
		!strings.Contains(resp, "protected mode") && !strings.Contains(resp, "DENIED") {
		return ""
	}
	// Fetch version (works when no auth is required).
	conn.SetDeadline(time.Now().Add(1 * time.Second))
	if _, err := conn.Write([]byte("INFO server\r\n")); err == nil {
		vbuf := make([]byte, 2048)
		if vn, err := conn.Read(vbuf); err == nil && vn > 0 {
			for _, line := range strings.Split(string(vbuf[:vn]), "\n") {
				if strings.HasPrefix(line, "redis_version:") {
					if v := strings.TrimSpace(strings.TrimPrefix(line, "redis_version:")); v != "" {
						return "Redis " + v
					}
				}
			}
		}
	}
	return "Redis"
}

// probeMemcached sends "version"; memcached replies "VERSION x.y.z".
func probeMemcached(ip, port string) string {
	conn, err := net.DialTimeout("tcp", dialTarget(ip, port), 1*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(1 * time.Second))
	if _, err := conn.Write([]byte("version\r\n")); err != nil {
		return ""
	}
	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return ""
	}
	resp := strings.TrimSpace(string(buf[:n]))
	if strings.HasPrefix(resp, "VERSION ") {
		return "Memcached " + strings.TrimSpace(strings.TrimPrefix(resp, "VERSION "))
	}
	return ""
}

// probeMongoDB sends a legacy OP_QUERY {isMaster:1}; MongoDB replies with an
// OP_REPLY whose BSON body contains isMaster/maxWireVersion markers.
func probeMongoDB(ip, port string) string {
	conn, err := net.DialTimeout("tcp", dialTarget(ip, port), 1*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()

	// BSON document { isMaster: 1 } (19 bytes).
	bson := []byte{
		0x13, 0x00, 0x00, 0x00, // document length
		0x10,                                         // int32 element
		'i', 's', 'M', 'a', 's', 't', 'e', 'r', 0x00, // field name
		0x01, 0x00, 0x00, 0x00, // value = 1
		0x00, // document terminator
	}
	coll := append([]byte("admin.$cmd"), 0x00)
	body := make([]byte, 0, 12+len(coll)+len(bson))
	body = append(body, 0, 0, 0, 0)             // flags
	body = append(body, coll...)                // fullCollectionName
	body = append(body, 0, 0, 0, 0)             // numberToSkip = 0
	body = append(body, 0xff, 0xff, 0xff, 0xff) // numberToReturn = -1
	body = append(body, bson...)

	msg := make([]byte, 16+len(body))
	binary.LittleEndian.PutUint32(msg[0:4], uint32(16+len(body))) // messageLength
	binary.LittleEndian.PutUint32(msg[4:8], 1)                    // requestID
	binary.LittleEndian.PutUint32(msg[8:12], 0)                   // responseTo
	binary.LittleEndian.PutUint32(msg[12:16], 2004)               // opCode OP_QUERY
	copy(msg[16:], body)

	conn.SetDeadline(time.Now().Add(1 * time.Second))
	if _, err := conn.Write(msg); err != nil {
		return ""
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n < 16 {
		return ""
	}
	resp := string(buf[:n])
	if strings.Contains(resp, "ismaster") || strings.Contains(resp, "isWritablePrimary") ||
		strings.Contains(resp, "maxWireVersion") || strings.Contains(resp, "topologyVersion") {
		return "MongoDB"
	}
	return ""
}

// probeMSSQL sends a TDS Pre-Login packet; SQL Server replies with a TDS
// response (type 0x04) whose VERSION option carries the server version.
func probeMSSQL(ip, port string) string {
	conn, err := net.DialTimeout("tcp", dialTarget(ip, port), 1*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()

	// Pre-Login payload: single VERSION option (token 0x00) + terminator.
	payload := []byte{
		0x00, 0x00, 0x06, 0x00, 0x06, // VERSION: offset=6, length=6
		0xff,             // options terminator
		0, 0, 0, 0, 0, 0, // VERSION data (6 bytes)
	}
	pkt := make([]byte, 8+len(payload))
	pkt[0] = 0x12 // type: PRELOGIN
	pkt[1] = 0x01 // status: EOM
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	copy(pkt[8:], payload)

	conn.SetDeadline(time.Now().Add(1 * time.Second))
	if _, err := conn.Write(pkt); err != nil {
		return ""
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n < 8 || buf[0] != 0x04 {
		return ""
	}
	// Parse the response payload for the VERSION option (token 0x00).
	if ver := parseTDSVersion(buf[8:n]); ver != "" {
		return "MSSQL " + ver
	}
	return "MSSQL"
}

// parseTDSVersion walks a Pre-Login response payload and returns "maj.min.build"
// from the VERSION option, or "" if it cannot be parsed.
func parseTDSVersion(p []byte) string {
	for pos := 0; pos+5 <= len(p); pos += 5 {
		token := p[pos]
		if token == 0xff {
			break
		}
		off := int(binary.BigEndian.Uint16(p[pos+1 : pos+3]))
		ln := int(binary.BigEndian.Uint16(p[pos+3 : pos+5]))
		if token == 0x00 && ln >= 4 && off+4 <= len(p) {
			major := p[off]
			minor := p[off+1]
			build := binary.BigEndian.Uint16(p[off+2 : off+4])
			return fmt.Sprintf("%d.%d.%d", major, minor, build)
		}
	}
	return ""
}

// probeOracle sends a TNS CONNECT packet; an Oracle listener replies with a TNS
// packet (Accept/Refuse/Redirect/Resend). The Refuse/data payload often carries
// the version (VSNNUM), which is decoded when present.
func probeOracle(ip, port string) string {
	conn, err := net.DialTimeout("tcp", dialTarget(ip, port), 1*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()

	connectData := []byte("(CONNECT_DATA=(COMMAND=version))")
	const dataOffset = 58
	pkt := make([]byte, dataOffset+len(connectData))
	pkt[4] = 0x01                                  // packet type: CONNECT
	binary.BigEndian.PutUint16(pkt[8:10], 0x0139)  // version
	binary.BigEndian.PutUint16(pkt[10:12], 0x012c) // version (compatible)
	binary.BigEndian.PutUint16(pkt[14:16], 0x0800) // session data unit
	binary.BigEndian.PutUint16(pkt[16:18], 0x7fff) // max transmission data unit
	binary.BigEndian.PutUint16(pkt[18:20], 0x4f98) // NT protocol characteristics
	binary.BigEndian.PutUint16(pkt[22:24], 0x0001) // value of 1 in hardware
	binary.BigEndian.PutUint16(pkt[24:26], uint16(len(connectData)))
	binary.BigEndian.PutUint16(pkt[26:28], dataOffset)
	pkt[32] = 0x01 // connect flags 0
	pkt[33] = 0x01 // connect flags 1
	copy(pkt[dataOffset:], connectData)
	binary.BigEndian.PutUint16(pkt[0:2], uint16(len(pkt))) // total length

	conn.SetDeadline(time.Now().Add(1 * time.Second))
	if _, err := conn.Write(pkt); err != nil {
		return ""
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n < 8 {
		return ""
	}
	// Response packet type at byte 4: 2=Accept, 4=Refuse, 5=Redirect, 11=Resend.
	switch buf[4] {
	case 0x02, 0x04, 0x05, 0x0b:
	default:
		return ""
	}
	if ver := parseOracleVersion(buf[8:n]); ver != "" {
		return "Oracle " + ver
	}
	return "Oracle"
}

// parseOracleVersion extracts a dotted version from a TNS response containing a
// "VSNNUM=<decimal>" token (a packed 32-bit version number), or "" if absent.
func parseOracleVersion(p []byte) string {
	s := string(p)
	idx := strings.Index(s, "VSNNUM=")
	if idx < 0 {
		return ""
	}
	rest := s[idx+len("VSNNUM="):]
	end := 0
	for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
		end++
	}
	if end == 0 {
		return ""
	}
	num, err := strconv.ParseUint(rest[:end], 10, 32)
	if err != nil || num == 0 {
		return ""
	}
	// VSNNUM packs version as nibbles/bytes: AABCCDD -> A.B.C.D
	v := uint32(num)
	return fmt.Sprintf("%d.%d.%d.%d", (v>>24)&0xff, (v>>20)&0x0f, (v>>12)&0xff, (v>>8)&0x0f)
}

// isPrintableASCII reports whether s is non-empty and all printable ASCII.
func isPrintableASCII(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// tryHTTP attempts an HTTP(S) request on a port, follows redirects, and returns title + TLS status.
func tryHTTP(ip, port string) *webProbeResult {
	conn, err := net.DialTimeout("tcp", dialTarget(ip, port), 1*time.Second)
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
		conn, err = net.DialTimeout("tcp", dialTarget(ip, port), 1*time.Second)
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
			newPath := loc
			// Handle absolute URL
			if strings.HasPrefix(loc, "http://") || strings.HasPrefix(loc, "https://") {
				// Extract host from URL
				scheme := "http://"
				if strings.HasPrefix(loc, "https://") {
					scheme = "https://"
				}
				rest := loc[len(scheme):]
				hostPart := rest
				pathStart := strings.Index(rest, "/")
				if pathStart != -1 {
					hostPart = rest[:pathStart]
					newPath = rest[pathStart:]
				} else {
					newPath = "/"
				}
				// Strip port from host if present
				redirectHost := hostPart
				if colonIdx := strings.LastIndex(hostPart, ":"); colonIdx != -1 {
					redirectHost = hostPart[:colonIdx]
				}
				// Skip if redirect goes to a different host
				if redirectHost != ip {
					// Resolve hostname to check if it's the same IP
					resolved, err := net.ResolveIPAddr("ip", redirectHost)
					if err != nil || resolved.String() != ip {
						return nil
					}
				}
				if scheme == "https://" && !isTLS {
					isTLS = true
				}
			}
			path = newPath

			// Reconnect for next request
			c, err := net.DialTimeout("tcp", dialTarget(ip, port), 1*time.Second)
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
// Prioritizes Version headers over Build headers.
func extractFromXHeaders(headers string) string {
	type match struct {
		name     string
		val      string
		priority int // 0=version (highest), 1=build, 2=name
	}
	var best *match

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

		var priority int
		if strings.HasSuffix(keyLower, "-version") || strings.HasSuffix(keyLower, "-api-version") {
			priority = 0
		} else if strings.HasSuffix(keyLower, "-build") {
			priority = 1
		} else if strings.HasSuffix(keyLower, "-name") && !strings.Contains(keyLower, "header") {
			priority = 2
		} else {
			continue
		}

		// Extract service name from header key
		name := key[2:] // strip "X-"
		for _, suffix := range []string{"-Version", "-version", "-Build", "-build",
			"-Api-Version", "-api-version", "-Name", "-name"} {
			if strings.HasSuffix(name, suffix) {
				name = name[:len(name)-len(suffix)]
				break
			}
		}
		name = strings.ReplaceAll(name, "-", " ")
		name = strings.TrimSpace(name)
		if name == "" || val == "" {
			continue
		}

		if best == nil || priority < best.priority {
			best = &match{name: name, val: val, priority: priority}
		}
	}

	if best == nil {
		return ""
	}
	if best.priority <= 1 { // version or build
		return fmt.Sprintf("%s %s", best.name, best.val)
	}
	return best.val // name
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
		// Skip object/array values
		if rest[0] == '{' || rest[0] == '[' {
			return ""
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
