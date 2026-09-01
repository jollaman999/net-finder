package netutil

import (
	"sync"
	"time"
)

// Limiter is a simple token-bucket rate limiter. It caps the rate of outbound
// probes so the scanner never bursts hard enough to trip switch storm-control
// or Dynamic ARP Inspection (DAI) thresholds.
type Limiter struct {
	tokens chan struct{}
	stop   chan struct{}
	rateCh chan int // requests to change the refill rate at runtime
}

// NewLimiter creates a limiter permitting perSec operations per second with a
// small burst allowance. perSec <= 0 returns nil (unlimited). The rate can be
// changed later with SetRate (the burst allowance stays fixed at creation).
func NewLimiter(perSec int) *Limiter {
	if perSec <= 0 {
		return nil
	}
	burst := perSec / 5
	if burst < 1 {
		burst = 1
	}
	l := &Limiter{
		tokens: make(chan struct{}, burst),
		stop:   make(chan struct{}),
		rateCh: make(chan int, 1),
	}
	go l.run(perSec)
	return l
}

func (l *Limiter) run(perSec int) {
	interval, perTick := tickParams(perSec)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-l.stop:
			return
		case n := <-l.rateCh:
			interval, perTick = tickParams(n)
			t.Reset(interval)
		case <-t.C:
			for i := 0; i < perTick; i++ {
				select {
				case l.tokens <- struct{}{}:
				default:
				}
			}
		}
	}
}

// tickParams picks a refill tick interval and the number of tokens to release per
// tick for a target rate. Above ~1000/sec a per-token tick would be throttled by
// timer resolution (~1ms), so it releases a batch of tokens on each 1ms tick.
func tickParams(perSec int) (time.Duration, int) {
	if perSec < 1 {
		perSec = 1
	}
	interval := time.Second / time.Duration(perSec)
	if interval < time.Millisecond {
		perTick := perSec / 1000
		if perTick < 1 {
			perTick = 1
		}
		return time.Millisecond, perTick
	}
	return interval, 1
}

// SetRate changes the refill rate (operations/sec) of a running limiter in
// place. A nil limiter is a no-op.
func (l *Limiter) SetRate(perSec int) {
	if l == nil {
		return
	}
	// Coalesce: keep only the most recent request.
	select {
	case <-l.rateCh:
	default:
	}
	select {
	case l.rateCh <- perSec:
	case <-l.stop:
	}
}

// Acquire blocks until the limiter permits one operation. A nil limiter is a
// no-op (unlimited).
func (l *Limiter) Acquire() {
	if l == nil {
		return
	}
	select {
	case <-l.tokens:
	case <-l.stop:
	}
}

// Stop halts the limiter's refill goroutine.
func (l *Limiter) Stop() {
	if l == nil {
		return
	}
	select {
	case <-l.stop:
	default:
		close(l.stop)
	}
}

// Process-wide limiters shared by every send path. Two classes because their
// safe thresholds differ wildly: ARP/broadcast must stay under DAI limits
// (often ~15 pps/port), while routed TCP/ICMP probes can go somewhat faster.
var (
	limiterMu       sync.RWMutex
	arpLimiter      *Limiter
	probeLimiter    *Limiter
	portScanLimiter *Limiter
	synScanLimiter  *Limiter
)

// SetARPRate configures the global ARP send rate (packets/sec). Keep this low
// (default 10) to stay under Dynamic ARP Inspection thresholds. n <= 0 disables.
func SetARPRate(perSec int) {
	limiterMu.Lock()
	defer limiterMu.Unlock()
	arpLimiter.Stop()
	arpLimiter = NewLimiter(perSec)
}

// SetProbeRate configures the global rate for routed probes and port-scan
// connections (packets/sec). n <= 0 disables.
func SetProbeRate(perSec int) {
	limiterMu.Lock()
	defer limiterMu.Unlock()
	probeLimiter.Stop()
	probeLimiter = NewLimiter(perSec)
}

// SetPortScanRate configures the global rate for the full TCP port-scan sweep
// (packets/sec). Kept lower than the general probe rate because a 1–65535 sweep
// against a single host is a classic port-scan signature. n <= 0 disables.
func SetPortScanRate(perSec int) {
	limiterMu.Lock()
	defer limiterMu.Unlock()
	portScanLimiter.Stop()
	portScanLimiter = NewLimiter(perSec)
}

// PortScanSetRate adjusts the running port-scan limiter's rate in place (used by
// the adaptive controller). n <= 0 is treated as 1.
func PortScanSetRate(perSec int) {
	limiterMu.RLock()
	l := portScanLimiter
	limiterMu.RUnlock()
	l.SetRate(perSec)
}

// SetSYNScanRate configures the global SYN-scan send rate (packets/sec). This can
// run much higher than the connect-scan rate because SYN scanning never blocks
// waiting per port. n <= 0 disables (unlimited).
func SetSYNScanRate(perSec int) {
	limiterMu.Lock()
	defer limiterMu.Unlock()
	synScanLimiter.Stop()
	synScanLimiter = NewLimiter(perSec)
}

// SYNScanAcquire blocks until the global SYN-scan limiter permits one send.
func SYNScanAcquire() {
	limiterMu.RLock()
	l := synScanLimiter
	limiterMu.RUnlock()
	l.Acquire()
}

// ARPAcquire blocks until the global ARP limiter permits one send.
func ARPAcquire() {
	limiterMu.RLock()
	l := arpLimiter
	limiterMu.RUnlock()
	l.Acquire()
}

// PortScanAcquire blocks until the global port-scan limiter permits one send.
func PortScanAcquire() {
	limiterMu.RLock()
	l := portScanLimiter
	limiterMu.RUnlock()
	l.Acquire()
}

// ProbeAcquire blocks until the global probe limiter permits one send.
func ProbeAcquire() {
	limiterMu.RLock()
	l := probeLimiter
	limiterMu.RUnlock()
	l.Acquire()
}
