package protocol

import (
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"net-finder/internal/netutil"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// l3ProbePorts are common TCP ports used for routed liveness detection. A host
// is considered alive if any of these accepts the connection OR actively
// refuses it (both prove the host's TCP stack is reachable). This catches
// Windows hosts that drop ICMP echo but keep 445/139/135/3389 reachable.
var l3ProbePorts = []int{445, 139, 135, 3389, 22, 80, 443, 3306, 5432, 1433, 1521, 6379, 27017, 8080, 23}

// L3ProbeScan discovers live hosts in routed (non-attached) subnets using
// normal L3 traffic from our real source IP — TCP connects plus a best-effort
// ICMP echo sweep. It never forges a source address, so it is indistinguishable
// from ordinary client traffic and does not trip DAI/port-security. All sends
// are globally rate-limited. Returns the set of alive IPs (MAC is unknowable
// across a router).
func L3ProbeScan(subnets []*net.IPNet, localIP net.IP, timeout time.Duration) map[string]bool {
	// Collect targets from remote subnets only (defensive: skip attached ones).
	var targets []net.IP
	for _, sn := range subnets {
		if localIP != nil && sn.Contains(localIP) {
			continue
		}
		targets = append(targets, netutil.ExpandCIDR(sn)...)
	}
	return L3ProbeIPs(targets, timeout)
}

// L3ProbeIPs probes a specific set of IPs for liveness via routed TCP connects
// and a best-effort ICMP echo sweep, from our real source IP. Used both for
// initial remote discovery and for cheap re-verification of known remote hosts.
func L3ProbeIPs(targets []net.IP, timeout time.Duration) map[string]bool {
	alive := make(map[string]bool)
	if len(targets) == 0 {
		return alive
	}
	var mu sync.Mutex
	markAlive := func(ip string) {
		mu.Lock()
		alive[ip] = true
		mu.Unlock()
	}

	// Best-effort ICMP echo sweep (requires raw-socket privilege; skipped if
	// unavailable). Runs concurrently with the TCP probes.
	var icmpWg sync.WaitGroup
	icmpDone := make(chan struct{})
	if c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0"); err == nil {
		icmpWg.Add(1)
		go func() {
			defer icmpWg.Done()
			defer c.Close()
			id := os.Getpid() & 0xffff

			// Reader: mark echo-reply sources alive until icmpDone.
			readerDone := make(chan struct{})
			go func() {
				defer close(readerDone)
				buf := make([]byte, 1500)
				for {
					select {
					case <-icmpDone:
						return
					default:
					}
					c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
					n, peer, err := c.ReadFrom(buf)
					if err != nil {
						continue
					}
					m, err := icmp.ParseMessage(1, buf[:n]) // 1 = ICMPv4
					if err != nil {
						continue
					}
					if m.Type == ipv4.ICMPTypeEchoReply {
						if ipAddr, ok := peer.(*net.IPAddr); ok {
							markAlive(ipAddr.IP.String())
						}
					}
				}
			}()

			for i, ip := range targets {
				netutil.ProbeAcquire()
				wm := icmp.Message{
					Type: ipv4.ICMPTypeEcho, Code: 0,
					Body: &icmp.Echo{ID: id, Seq: i & 0xffff, Data: []byte("net-finder")},
				}
				b, err := wm.Marshal(nil)
				if err != nil {
					continue
				}
				c.WriteTo(b, &net.IPAddr{IP: ip})
			}
			// Give replies time to arrive, then stop the reader.
			time.Sleep(timeout)
			close(icmpDone)
			<-readerDone
		}()
	} else {
		close(icmpDone)
	}

	// TCP connect probes: worker pool, each connection globally rate-limited.
	tcpTimeout := 1 * time.Second
	jobs := make(chan net.IP, 256)
	var wg sync.WaitGroup
	workers := 64
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				ipStr := ip.String()
				for _, port := range l3ProbePorts {
					mu.Lock()
					done := alive[ipStr]
					mu.Unlock()
					if done {
						break
					}
					netutil.ProbeAcquire()
					conn, err := net.DialTimeout("tcp", net.JoinHostPort(ipStr, strconv.Itoa(port)), tcpTimeout)
					if err == nil {
						conn.Close()
						markAlive(ipStr)
						break
					}
					// A refused connection still proves the host is alive.
					if strings.Contains(err.Error(), "refused") {
						markAlive(ipStr)
						break
					}
				}
			}
		}()
	}
	for _, ip := range targets {
		jobs <- ip
	}
	close(jobs)
	wg.Wait()

	<-icmpDone
	icmpWg.Wait()

	return alive
}
