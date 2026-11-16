// Package session implements L3/L4 (ТЗ раздел 8-9): a session spans a
// pool of L0-L2 connections, numbers every frame, retransmits DATA frames
// across the pool on ACK timeout, adapts each connection's byte budget,
// and migrates by opening fresh connections when the pool dies — plus
// stream multiplexing on top (package stream.go).
//
// Phase-3 scope (not here, see ROADMAP.md): per-stream flow-control
// windows, UDP datagrams, traffic shaping/padding, and PSK-based faster
// reattachment.
package session

import (
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/veritesclaude/svo-govno/pkg/poisonproto/crypto"
	"github.com/veritesclaude/svo-govno/pkg/poisonproto/frame"
)

// Config holds the tunables ТЗ §14's subscription config exposes for L3
// (section "session"): pool size, per-connection byte budget, whether the
// budget adapts, and the ACK-timeout range.
type Config struct {
	PoolMin, PoolMax             int
	BudgetMin, BudgetMax         int
	Adaptive                     bool
	AckTimeoutMin, AckTimeoutMax time.Duration
}

// DefaultConfig matches the ТЗ §14 example defaults.
func DefaultConfig() Config {
	return Config{
		PoolMin: 4, PoolMax: 8,
		BudgetMin: 9000, BudgetMax: 14000,
		Adaptive:      true,
		AckTimeoutMin: 300 * time.Millisecond,
		AckTimeoutMax: 500 * time.Millisecond,
	}
}

// Session multiplexes streams over a pool of connections to one peer
// (see package doc).
type Session struct {
	id        ID
	initiator bool
	dialer    Dialer
	cfg       Config

	connsMu     sync.Mutex
	conns       map[uint64]*poolConn
	nextConnID  uint64
	pickCounter atomic.Uint64

	budget *budgetController
	rtt    *rttEstimator

	seq atomic.Uint64

	relMu      sync.Mutex
	unacked    map[uint64]*pendingFrame
	recvSeen   map[uint64]struct{}
	cumulative uint64

	mu           sync.Mutex
	streams      map[uint32]*Stream
	nextStreamID uint32

	acceptCh  chan *Stream
	closeOnce sync.Once
	closed    chan struct{}
	runErr    error
}

// New establishes the SESSION_ATTACH handshake on firstConn (which must
// already be past L0-L2) and starts the pool/reliability machinery. As
// initiator, id is this session's freshly generated ID; as responder, id
// is ignored — the real ID is learned from the peer, and the returned
// Session's ID() reflects that. dialer opens additional connections for
// pool growth and migration (ТЗ §8.1, §8.4); pass nil to disable both
// (the server side never dials the client).
func New(id ID, firstConn *crypto.Conn, initiator bool, cfg Config, dialer Dialer) (*Session, error) {
	if initiator {
		if err := sendAttachRequest(firstConn, id); err != nil {
			return nil, err
		}
		if err := readAttachReply(firstConn, id); err != nil {
			return nil, err
		}
		return NewFromAttached(id, firstConn, true, cfg, dialer), nil
	}

	gotID, err := ReadAttach(firstConn)
	if err != nil {
		return nil, err
	}
	if err := CompleteAttach(firstConn, gotID); err != nil {
		return nil, err
	}
	return NewFromAttached(gotID, firstConn, false, cfg, dialer), nil
}

// NewFromAttached constructs a session around a first connection that has
// ALREADY completed the SESSION_ATTACH handshake on both sides (both
// agree on id). This is what a server-side session registry uses: it
// must read the attach ID itself (session.ReadAttach) to decide whether
// this connection starts a new session or joins one already running,
// before either path can construct/extend anything — see
// transport.Server. New is a convenience wrapper around this for callers
// (the client, and tests) that don't need to inspect the ID first.
func NewFromAttached(id ID, firstConn *crypto.Conn, initiator bool, cfg Config, dialer Dialer) *Session {
	s := &Session{
		id:           id,
		initiator:    initiator,
		dialer:       dialer,
		cfg:          cfg,
		conns:        make(map[uint64]*poolConn),
		nextConnID:   1,
		budget:       newBudgetController(cfg.BudgetMin, cfg.BudgetMax, cfg.Adaptive),
		rtt:          newRTTEstimator(cfg.AckTimeoutMin, cfg.AckTimeoutMax),
		unacked:      make(map[uint64]*pendingFrame),
		recvSeen:     make(map[uint64]struct{}),
		streams:      make(map[uint32]*Stream),
		nextStreamID: 1,
		acceptCh:     make(chan *Stream, 16),
		closed:       make(chan struct{}),
	}
	s.AddConn(firstConn)
	go s.maintainPool()
	go s.retransmitLoop()
	go s.ackLoop()
	return s
}

func (s *Session) ID() ID { return s.id }

// Run blocks until the session ends (every pool connection is gone with
// no dialer able to replace them, or Close was called) and returns the
// reason. All actual I/O happens in background goroutines started by New.
func (s *Session) Run() error {
	<-s.closed
	return s.runErr
}

// Done reports when the session has stopped.
func (s *Session) Done() <-chan struct{} { return s.closed }

// Close ends the session locally without a clean L3 teardown message
// (graceful multi-connection teardown framing is a phase-3 refinement).
func (s *Session) Close() error {
	s.shutdown(io.ErrClosedPipe)
	return nil
}

func (s *Session) shutdown(err error) {
	s.closeOnce.Do(func() {
		s.runErr = err
		close(s.closed)

		s.connsMu.Lock()
		conns := make([]*poolConn, 0, len(s.conns))
		for _, pc := range s.conns {
			conns = append(conns, pc)
		}
		s.connsMu.Unlock()
		for _, pc := range conns {
			_ = pc.conn.Close()
		}

		s.mu.Lock()
		for _, st := range s.streams {
			st.closeLocal(io.EOF)
		}
		s.mu.Unlock()
	})
}

// readLoop pumps frames off one pool connection until it errors, then
// evicts it (ТЗ §8.3/§8.4 treat a dead connection the same whether it died
// outright or just stopped answering).
func (s *Session) readLoop(pc *poolConn) {
	for {
		pt, err := pc.conn.Open(nil)
		if err != nil {
			s.evictConnection(pc)
			return
		}
		f, err := frame.Decode(pt)
		if err != nil {
			s.evictConnection(pc)
			return
		}
		s.accountRecv(pc, len(pt))
		s.dispatch(f, pc)
	}
}

func (s *Session) dispatch(f *frame.Frame, pc *poolConn) {
	isNew := s.noteReceived(f.Seq)

	switch f.Type {
	case frame.TypeData:
		if isNew {
			s.dispatchData(f)
		}
	case frame.TypeACK:
		if isNew {
			s.handleAck(f)
		}
	case frame.TypeOpenStream:
		if isNew {
			s.handleOpenStream(f)
		}
	case frame.TypeCloseStream:
		if isNew {
			s.handleCloseStream(f)
		}
	case frame.TypePing:
		_ = s.sendRaw(frame.TypePing, f.StreamID, f.Data) // echo = pong
	case frame.TypeRekey:
		pc.conn.RekeyRecv()
	case frame.TypeSessionAttach:
		// A stray/duplicate attach on an already-running connection; ignore.
	case frame.TypePaddingOnly, frame.TypeWindowUpdate:
		// Shaping (L5) and per-stream flow control are phase 3.
	}
}

// sendOn seals buf onto one specific pool connection, driving that
// connection's own L2 rekey at the boundary first (ТЗ §7 keys are per
// connection, not per session) and accounting its send budget (ТЗ §8.2).
func (s *Session) sendOn(pc *poolConn, buf []byte, dataLen int) error {
	pc.writeMu.Lock()
	defer pc.writeMu.Unlock()

	if pc.conn.ShouldRekeySend() {
		rbuf, err := frame.Encode(nil, &frame.Frame{Type: frame.TypeRekey})
		if err == nil {
			if err := pc.conn.Seal(rbuf, nil); err == nil {
				pc.conn.RekeySend()
			}
		}
	}

	if err := pc.conn.Seal(buf, nil); err != nil {
		s.evictConnection(pc)
		return err
	}
	s.accountSend(pc, dataLen)
	return nil
}

// sendRaw encodes and sends one frame. DATA frames are tracked for
// retransmission (ТЗ §8.3); every other type is sent best-effort once.
func (s *Session) sendRaw(typ frame.Type, streamID uint32, data []byte) error {
	seq := s.seq.Add(1)
	buf, err := frame.Encode(nil, &frame.Frame{Type: typ, StreamID: streamID, Seq: seq, Data: data})
	if err != nil {
		return err
	}

	if typ == frame.TypeData {
		pf := &pendingFrame{seq: seq, streamID: streamID, data: append([]byte(nil), data...)}
		s.relMu.Lock()
		s.unacked[seq] = pf
		s.relMu.Unlock()
		// A total failure here is not an error to the caller (ТЗ §8.4: a
		// pool hiccup must not break user streams) — the frame stays in
		// `unacked` with a zero sentAt, which the retransmit loop treats
		// as immediately overdue and retries as soon as any connection is
		// available again.
		s.trySend(pf, buf)
		return nil
	}

	pc := s.pickConn(nil)
	if pc == nil {
		return fmt.Errorf("session: no live connection")
	}
	return s.sendOn(pc, buf, len(data))
}
