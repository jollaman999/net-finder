package netutil

import (
	"sync"
	"time"
)

// portScanAdaptive is a delay-based (TCP Vegas-like) congestion controller for
// the port-scan send rate. It watches the round-trip latency of ports that
// actually respond (SYN-ACK or RST) and keeps the rate as high as it can without
// inflating that latency: when the responsive-port RTT climbs well above the
// best-observed baseline it multiplicatively backs off; when latency stays near
// baseline it additively ramps up, bounded by [floor, ceil].
//
// Only responsive samples drive the controller. Connect timeouts are ignored:
// for a TCP-connect scan a timeout almost always means a firewall-filtered port,
// not congestion, so it carries no reliable delay signal.
type portScanAdaptive struct {
	mu      sync.Mutex
	floor   int
	ceil    int
	cur     int
	baseRTT time.Duration // best (minimum) responsive RTT observed
	rttSum  time.Duration
	rttN    int
	lastAdj time.Time
}

const (
	psWindow    = 150                    // responsive samples before an adjustment
	psMinWindow = 20                     // minimum samples for a time-based adjustment
	psInterval  = 750 * time.Millisecond // fallback cadence when samples are sparse
	psBackoffHi = 3.0                    // avg/base above this ⇒ congested ⇒ back off
	psRampLo    = 1.5                    // avg/base below this ⇒ healthy ⇒ ramp up
)

var (
	psAdaptMu sync.Mutex
	psAdapt   *portScanAdaptive
)

// EnablePortScanAdaptive turns on adaptive port-scan rate control within
// [floor, ceil] conns/sec, starting at `start`. It (re)creates the shared
// port-scan limiter at ceil — so the burst allowance is sized for the ceiling —
// then dials it down to the starting rate.
func EnablePortScanAdaptive(floor, ceil, start int) {
	if floor < 1 {
		floor = 1
	}
	if ceil < floor {
		ceil = floor
	}
	if start < floor {
		start = floor
	}
	if start > ceil {
		start = ceil
	}
	SetPortScanRate(ceil)  // create the limiter with burst sized for the ceiling
	PortScanSetRate(start) // then dial down to the starting rate

	psAdaptMu.Lock()
	psAdapt = &portScanAdaptive{floor: floor, ceil: ceil, cur: start, lastAdj: time.Now()}
	psAdaptMu.Unlock()
}

// PortScanObserve feeds one connect outcome to the adaptive controller. rtt is
// the measured round-trip time; responded is true only when the port answered
// (successful connect or explicit refusal) and false on timeout. A no-op when
// adaptive control is disabled.
func PortScanObserve(rtt time.Duration, responded bool) {
	psAdaptMu.Lock()
	a := psAdapt
	psAdaptMu.Unlock()
	if a == nil || !responded || rtt <= 0 {
		return
	}
	a.observe(rtt)
}

func (a *portScanAdaptive) observe(rtt time.Duration) {
	a.mu.Lock()
	if a.baseRTT == 0 || rtt < a.baseRTT {
		a.baseRTT = rtt
	}
	a.rttSum += rtt
	a.rttN++

	ready := a.rttN >= psWindow ||
		(a.rttN >= psMinWindow && time.Since(a.lastAdj) >= psInterval)
	if !ready {
		a.mu.Unlock()
		return
	}

	avg := a.rttSum / time.Duration(a.rttN)
	// Floor the baseline: on a LAN the best RTT is sub-millisecond, so without a
	// floor ordinary scheduling jitter would inflate the ratio and trigger false
	// backoff. Only genuine queue buildup (tens of ms) should register.
	base := a.baseRTT
	if base < 2*time.Millisecond {
		base = 2 * time.Millisecond
	}
	prev := a.cur
	next := prev
	switch ratio := float64(avg) / float64(base); {
	case ratio > psBackoffHi:
		next = prev * 3 / 4 // multiplicative decrease
	case ratio < psRampLo:
		next = prev + prev/5 + 25 // additive increase
	}
	if next < a.floor {
		next = a.floor
	}
	if next > a.ceil {
		next = a.ceil
	}
	a.cur = next
	a.rttSum = 0
	a.rttN = 0
	a.lastAdj = time.Now()
	a.mu.Unlock()

	if next != prev {
		PortScanSetRate(next)
	}
}
