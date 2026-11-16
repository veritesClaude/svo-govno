package session

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/veritesclaude/svo-govno/pkg/poisonproto/crypto"
)

// Dialer opens and fully establishes (L0 through L2) one additional
// connection to this session's peer, ready to be attached to the pool —
// ТЗ §8.1 ("пул из N TCP+TLS соединений") and §8.4 (migration: opening
// fresh connections when the pool dies). Supplied by package transport,
// which is the only layer that knows how to dial and mask a connection.
// A nil Dialer disables pool growth and migration (used on the server
// side, which never dials out to a client, and in tests).
type Dialer func() (*crypto.Conn, error)

// poolConn is one physical connection in the session's pool, with its own
// independent per-direction byte budget (ТЗ §8.2).
type poolConn struct {
	id   uint64
	conn *crypto.Conn

	writeMu sync.Mutex

	sendRemaining atomic.Int64
	recvRemaining atomic.Int64
	sendUnlimited bool
	recvUnlimited bool

	dead           atomic.Bool
	retiredCleanly atomic.Bool
}

// AddConn registers an already-attached connection into the pool, draws
// its budget, and starts reading from it.
func (s *Session) AddConn(c *crypto.Conn) *poolConn {
	s.connsMu.Lock()
	id := s.nextConnID
	s.nextConnID++
	sb := s.budget.draw()
	rb := s.budget.draw()
	pc := &poolConn{id: id, conn: c, sendUnlimited: sb == 0, recvUnlimited: rb == 0}
	pc.sendRemaining.Store(sb)
	pc.recvRemaining.Store(rb)
	s.conns[id] = pc
	s.connsMu.Unlock()

	go s.readLoop(pc)
	return pc
}

func (s *Session) getConn(id uint64) *poolConn {
	s.connsMu.Lock()
	defer s.connsMu.Unlock()
	return s.conns[id]
}

// LiveConnCount reports how many pool connections are neither dead nor
// retiring — used by transport.Server to know when a session has been
// without any connection long enough to reap (ТЗ §8.4: "до 60 секунд").
func (s *Session) LiveConnCount() int { return s.liveConnCount() }

func (s *Session) liveConnCount() int {
	s.connsMu.Lock()
	defer s.connsMu.Unlock()
	n := 0
	for _, pc := range s.conns {
		if !pc.dead.Load() && !pc.retiredCleanly.Load() {
			n++
		}
	}
	return n
}

// pickConn returns a usable pool connection for the next outgoing frame,
// spreading load round-robin over everything that's neither dead nor
// retiring. exclude may be nil.
func (s *Session) pickConn(exclude map[uint64]bool) *poolConn {
	s.connsMu.Lock()
	defer s.connsMu.Unlock()

	var candidates []*poolConn
	for _, pc := range s.conns {
		if pc.dead.Load() || pc.retiredCleanly.Load() {
			continue
		}
		if exclude != nil && exclude[pc.id] {
			continue
		}
		candidates = append(candidates, pc)
	}
	if len(candidates) == 0 {
		return nil
	}
	idx := int(s.pickCounter.Add(1) % uint64(len(candidates)))
	return candidates[idx]
}

// accountSend/accountRecv implement the budget side of ТЗ §8.2: once
// either direction's budget is spent, the connection retires (closes
// normally) rather than being used further.
func (s *Session) accountSend(pc *poolConn, n int) {
	if pc.sendUnlimited || n == 0 {
		return
	}
	if pc.sendRemaining.Add(-int64(n)) <= 0 {
		s.retireCleanly(pc)
	}
}

func (s *Session) accountRecv(pc *poolConn, n int) {
	if pc.recvUnlimited || n == 0 {
		return
	}
	if pc.recvRemaining.Add(-int64(n)) <= 0 {
		s.retireCleanly(pc)
	}
}

// retireCleanly marks pc so it is no longer picked for new sends, credits
// the adaptive budget controller for a clean (non-freeze) exhaustion, and
// schedules the actual close after a short grace window so frames already
// in flight on it get a chance to be ACKed (ТЗ §8.2: "закрывается штатно
// (close_notify)", as opposed to a freeze).
func (s *Session) retireCleanly(pc *poolConn) {
	if !pc.retiredCleanly.CompareAndSwap(false, true) {
		return
	}
	s.budget.onCleanRetire()
	s.growIfNeeded()

	grace := 2 * s.rtt.timeout()
	go func() {
		select {
		case <-time.After(grace):
		case <-s.closed:
		}
		s.evictConnection(pc)
	}()
}

// evictConnection is the single place a pool connection actually goes
// away, whether from a graceful budget retirement, a read/write error, or
// the retransmit loop presuming it frozen (ТЗ §8.3). It is safe to call
// more than once or concurrently for the same pc.
func (s *Session) evictConnection(pc *poolConn) {
	if !pc.dead.CompareAndSwap(false, true) {
		return
	}
	_ = pc.conn.Close()
	if !pc.retiredCleanly.Load() {
		s.budget.onFreeze()
	}
	s.connsMu.Lock()
	delete(s.conns, pc.id)
	s.connsMu.Unlock()
	s.growIfNeeded()
}

// maintainPool keeps at least cfg.PoolMin live connections for as long as
// a Dialer is configured (ТЗ §8.1, §8.4).
func (s *Session) maintainPool() {
	s.growIfNeeded()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.closed:
			return
		case <-ticker.C:
			s.growIfNeeded()
		}
	}
}

func (s *Session) growIfNeeded() {
	if s.dialer == nil {
		return
	}
	need := s.cfg.PoolMin - s.liveConnCount()
	for i := 0; i < need; i++ {
		go s.spawnConn()
	}
}

func (s *Session) spawnConn() {
	select {
	case <-s.closed:
		return
	default:
	}
	c, err := s.dialer()
	if err != nil {
		return // maintainPool's next tick retries
	}
	if err := sendAttachRequest(c, s.id); err != nil {
		_ = c.Close()
		return
	}
	if err := readAttachReply(c, s.id); err != nil {
		_ = c.Close()
		return
	}
	s.AddConn(c)
}
