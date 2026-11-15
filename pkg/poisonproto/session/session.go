// Package session implements L3 (ТЗ раздел 8): frame sequencing and stream
// multiplexing on top of the L2 crypto.Conn.
//
// Phase-1 scope only: ТЗ §17 п.1 calls for "простая сессия через одно
// соединение" (a simple session over a single connection). The connection
// pool, per-connection byte budget, ACK-timeout retransmission across the
// pool, and migration (ТЗ §8.2–8.4) are phase 2 and deliberately not here —
// see ROADMAP.md. What this package does implement for real: the session
// handshake (SESSION_ATTACH), stream open/data/close multiplexing, PING
// echo, and driving L2 REKEY at the agreed frame boundary.
package session

import (
	"crypto/rand"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	"github.com/veritesclaude/svo-govno/pkg/poisonproto/crypto"
	"github.com/veritesclaude/svo-govno/pkg/poisonproto/frame"
)

// ID is a session identifier (ТЗ §8.1: "случайный ID 16 байт").
type ID [16]byte

func NewID() (ID, error) {
	var id ID
	_, err := rand.Read(id[:])
	return id, err
}

// Session multiplexes streams over one crypto.Conn (see package doc for
// phase-1 scope).
type Session struct {
	id        ID
	conn      *crypto.Conn
	initiator bool

	writeMu sync.Mutex // serializes L2 Seal calls (nonce must advance in order)

	mu           sync.Mutex
	streams      map[uint32]*Stream
	nextStreamID uint32

	acceptCh  chan *Stream
	closeOnce sync.Once
	closed    chan struct{}
	runErr    error

	seq atomic.Uint64 // ТЗ §8.3: frame number is per-session, not per-stream
}

func New(id ID, conn *crypto.Conn, initiator bool) *Session {
	return &Session{
		id:           id,
		conn:         conn,
		initiator:    initiator,
		streams:      make(map[uint32]*Stream),
		acceptCh:     make(chan *Stream, 16),
		closed:       make(chan struct{}),
		nextStreamID: 1,
	}
}

func (s *Session) ID() ID { return s.id }

// Attach performs the SESSION_ATTACH exchange: the initiator announces its
// session ID; the responder echoes it back so both sides know the L3
// channel is alive end to end. Phase 2 reuses this same frame to reattach
// an existing session to a fresh connection after migration.
func (s *Session) Attach() error {
	if s.initiator {
		if err := s.sendRaw(frame.TypeSessionAttach, 0, s.id[:]); err != nil {
			return err
		}
		f, err := s.readOne()
		if err != nil {
			return err
		}
		if f.Type != frame.TypeSessionAttach || ID(f.Data[:16]) != s.id {
			return fmt.Errorf("session: attach reply mismatch")
		}
		return nil
	}

	f, err := s.readOne()
	if err != nil {
		return err
	}
	if f.Type != frame.TypeSessionAttach || len(f.Data) < 16 {
		return fmt.Errorf("session: expected SESSION_ATTACH, got %s", f.Type)
	}
	copy(s.id[:], f.Data[:16])
	return s.sendRaw(frame.TypeSessionAttach, 0, s.id[:])
}

// Run reads frames until the connection fails and dispatches them. It
// blocks; callers run it in its own goroutine and use AcceptStream /
// Stream.Read/Write from others.
func (s *Session) Run() error {
	for {
		f, err := s.readOne()
		if err != nil {
			s.shutdown(err)
			return err
		}
		switch f.Type {
		case frame.TypeData:
			s.dispatchData(f)
		case frame.TypeOpenStream:
			s.handleOpenStream(f)
		case frame.TypeCloseStream:
			s.handleCloseStream(f)
		case frame.TypeACK:
			// Phase 1 generates ACKs for visibility but does not yet act on
			// them (no retransmission without a connection pool to
			// retransmit onto) — phase 2.
		case frame.TypePing:
			_ = s.sendRaw(frame.TypePing, f.StreamID, f.Data) // echo = pong
		case frame.TypeRekey:
			s.conn.RekeyRecv()
		case frame.TypeSessionAttach:
			// Duplicate post-handshake attach; ignore in phase 1.
		case frame.TypePaddingOnly, frame.TypeWindowUpdate:
			// Shaping (L5) and per-stream flow control are phase 3.
		}
	}
}

// No AEAD associated data is used for L3 records: the session ID itself is
// the first thing exchanged (SESSION_ATTACH), so the responder doesn't know
// it yet when decrypting that very first record, and each L1 connection
// already gets a fresh Noise handshake (fresh keys) so binding records to
// a session ID isn't needed for phase-1's single-connection model.
func (s *Session) readOne() (*frame.Frame, error) {
	pt, err := s.conn.Open(nil)
	if err != nil {
		return nil, err
	}
	return frame.Decode(pt)
}

// sendRaw encodes and seals one frame, driving L2 rekey at the boundary
// (ТЗ §7) immediately beforehand so sender and receiver rotate in lockstep.
func (s *Session) sendRaw(typ frame.Type, streamID uint32, data []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	if typ != frame.TypeRekey && s.conn.ShouldRekeySend() {
		buf, err := frame.Encode(nil, &frame.Frame{Type: frame.TypeRekey, StreamID: 0})
		if err != nil {
			return err
		}
		if err := s.conn.Seal(buf, nil); err != nil {
			return err
		}
		s.conn.RekeySend()
	}

	seq := s.seq.Add(1)
	buf, err := frame.Encode(nil, &frame.Frame{Type: typ, StreamID: streamID, Seq: seq, Data: data})
	if err != nil {
		return err
	}
	return s.conn.Seal(buf, nil)
}

func (s *Session) shutdown(err error) {
	s.closeOnce.Do(func() {
		s.runErr = err
		close(s.closed)
		s.mu.Lock()
		for _, st := range s.streams {
			st.closeLocal(io.EOF)
		}
		s.mu.Unlock()
	})
}

// Close ends the session locally without a clean L3 teardown message
// (phase 1; graceful shutdown framing is phase 2).
func (s *Session) Close() error {
	s.shutdown(io.ErrClosedPipe)
	return nil
}

// Done reports when the session has stopped (connection failed or closed).
func (s *Session) Done() <-chan struct{} { return s.closed }
