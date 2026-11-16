package session

import (
	"crypto/rand"
	"encoding/binary"
	"sync"
)

// budgetController implements the adaptive per-connection byte budget
// (ТЗ §8.2): each pool connection gets a random budget drawn from a
// [min,max] range before it must retire; absent freezes the range grows
// toward unlimited, and the first freeze resets it to the configured
// minimum.
type budgetController struct {
	mu                 sync.Mutex
	cfgMin, cfgMax     int64
	curMin, curMax     int64
	adaptive           bool
	unlimited          bool
	cleanRetiresInARow int
}

// growAfterCleanRetires is how many budget-exhaustion retirements (not
// freezes) in a row it takes before doubling the range — ТЗ §8.2 only
// says growth is gradual, so this is a deliberately simple, documented
// heuristic rather than a prescribed algorithm.
const growAfterCleanRetires = 3

// unlimitedCeiling is the range ceiling past which the controller just
// treats the connection as unbudgeted rather than drawing an ever-larger
// random range.
const unlimitedCeiling = 64 * 1024 * 1024

func newBudgetController(cfgMin, cfgMax int, adaptive bool) *budgetController {
	return &budgetController{
		cfgMin: int64(cfgMin), cfgMax: int64(cfgMax),
		curMin: int64(cfgMin), curMax: int64(cfgMax),
		adaptive: adaptive,
	}
}

// draw returns a fresh random budget (bytes) for a new pool connection, or
// a sentinel of 0 meaning "unlimited" (the caller should not retire this
// connection for budget reasons at all).
func (b *budgetController) draw() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.unlimited {
		return 0
	}
	span := b.curMax - b.curMin
	if span <= 0 {
		return b.curMin
	}
	var buf [8]byte
	_, _ = rand.Read(buf[:])
	offset := int64(binary.BigEndian.Uint64(buf[:]) % uint64(span+1))
	return b.curMin + offset
}

// onFreeze reports a connection was presumed frozen (missed its ACK
// deadline) rather than retired cleanly — ТЗ §8.2: "При первой заморозке
// возвращается к минимуму."
func (b *budgetController) onFreeze() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.curMin, b.curMax = b.cfgMin, b.cfgMax
	b.unlimited = false
	b.cleanRetiresInARow = 0
}

// onCleanRetire reports a connection exhausted its budget and closed
// normally, with no freeze observed on it — ТЗ §8.2: "Если её нет...
// бюджет увеличивается постепенно вплоть до неограниченного."
func (b *budgetController) onCleanRetire() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.adaptive {
		return
	}
	b.cleanRetiresInARow++
	if b.cleanRetiresInARow < growAfterCleanRetires {
		return
	}
	b.cleanRetiresInARow = 0
	if b.curMax >= unlimitedCeiling {
		b.unlimited = true
		return
	}
	b.curMin *= 2
	b.curMax *= 2
}
