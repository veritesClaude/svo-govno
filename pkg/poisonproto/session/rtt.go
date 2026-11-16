package session

import (
	"sync"
	"time"
)

// rttEstimator is a minimal TCP-SRTT-style smoothed RTT tracker, used to
// compute the ACK-timeout that decides when a connection is presumed
// frozen (ТЗ §8.3: "Нет ACK за 300–500 мс (зависит от RTT)").
type rttEstimator struct {
	mu     sync.Mutex
	srtt   time.Duration
	have   bool
	cfgMin time.Duration
	cfgMax time.Duration
}

func newRTTEstimator(cfgMin, cfgMax time.Duration) *rttEstimator {
	return &rttEstimator{cfgMin: cfgMin, cfgMax: cfgMax}
}

// sample feeds one round-trip-time observation in. Only call this with
// samples from frames that were never retransmitted — a retransmitted
// frame's ACK can't be attributed to a specific transmission (Karn's
// algorithm), so callers must filter those out themselves.
func (r *rttEstimator) sample(rtt time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.have {
		r.srtt = rtt
		r.have = true
		return
	}
	// Standard TCP-like EWMA, alpha = 1/8.
	r.srtt = r.srtt + (rtt-r.srtt)/8
}

// timeout returns the current ACK-timeout: 4x the smoothed RTT, clamped
// to the configured [min,max] range (ТЗ §8.3's default 300–500ms). Before
// any sample exists, it conservatively returns cfgMax so a cold session
// doesn't mistake normal first-contact latency for a freeze.
func (r *rttEstimator) timeout() time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.have {
		return r.cfgMax
	}
	t := r.srtt * 4
	if t < r.cfgMin {
		return r.cfgMin
	}
	if t > r.cfgMax {
		return r.cfgMax
	}
	return t
}
