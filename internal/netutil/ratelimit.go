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
}

// NewLimiter creates a limiter permitting perSec operations per second with a
// small burst allowance. perSec <= 0 returns nil (unlimited).
func NewLimiter(perSec int) *Limiter {
	if perSec <= 0 {
		return nil
	}
	burst := perSec / 5
	if burst < 1 {
		burst = 1
	}
	interval := time.Second / time.Duration(perSec)
	if interval <= 0 {
		interval = time.Microsecond
	}
	l := &Limiter{
		tokens: make(chan struct{}, burst),
		stop:   make(chan struct{}),
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-l.stop:
				return
			case <-t.C:
				select {
				case l.tokens <- struct{}{}:
				default:
				}
			}
		}
	}()
	return l
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
