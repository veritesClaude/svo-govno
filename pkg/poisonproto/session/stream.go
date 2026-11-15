package session

import (
	"io"
	"sync"

	"github.com/veritesclaude/svo-govno/pkg/poisonproto/frame"
)

// Stream is one user TCP/UDP connection multiplexed over the session (ТЗ
// раздел 9 — L4). Per-stream flow-control windows and UDP datagram
// handling are phase 3; this is a plain ordered byte stream for now.
type Stream struct {
	id      uint32
	session *Session
	Network frame.Network
	Addr    string

	readCh chan []byte
	left   []byte // unread remainder of the last chunk pulled off readCh

	closeOnce sync.Once
	closed    chan struct{}
	closeErr  error
}

func newStream(id uint32, s *Session, network frame.Network, addr string) *Stream {
	return &Stream{
		id:      id,
		session: s,
		Network: network,
		Addr:    addr,
		readCh:  make(chan []byte, 64),
		closed:  make(chan struct{}),
	}
}

// OpenStream asks the peer to open network/addr and returns a Stream the
// caller can immediately Read/Write.
func (s *Session) OpenStream(network frame.Network, addr string) (*Stream, error) {
	id := s.allocStreamID()
	st := newStream(id, s, network, addr)

	s.mu.Lock()
	s.streams[id] = st
	s.mu.Unlock()

	payload := (&frame.OpenStreamPayload{Network: network, Addr: addr}).Encode()
	if err := s.sendRaw(frame.TypeOpenStream, id, payload); err != nil {
		s.mu.Lock()
		delete(s.streams, id)
		s.mu.Unlock()
		return nil, err
	}
	return st, nil
}

func (s *Session) allocStreamID() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := s.nextStreamID
	s.nextStreamID++
	return id
}

// AcceptStream returns the next inbound OPEN_STREAM request (server side).
func (s *Session) AcceptStream() (*Stream, error) {
	select {
	case st := <-s.acceptCh:
		return st, nil
	case <-s.closed:
		return nil, io.EOF
	}
}

func (s *Session) handleOpenStream(f *frame.Frame) {
	op, err := frame.DecodeOpenStreamPayload(f.Data)
	if err != nil {
		return
	}
	st := newStream(f.StreamID, s, op.Network, op.Addr)
	s.mu.Lock()
	s.streams[f.StreamID] = st
	s.mu.Unlock()
	select {
	case s.acceptCh <- st:
	case <-s.closed:
	}
}

func (s *Session) handleCloseStream(f *frame.Frame) {
	s.mu.Lock()
	st := s.streams[f.StreamID]
	delete(s.streams, f.StreamID)
	s.mu.Unlock()
	if st != nil {
		st.closeLocal(io.EOF)
	}
}

func (s *Session) dispatchData(f *frame.Frame) {
	s.mu.Lock()
	st := s.streams[f.StreamID]
	s.mu.Unlock()
	if st == nil {
		return // stream already closed locally; drop
	}
	data := make([]byte, len(f.Data))
	copy(data, f.Data)
	select {
	case st.readCh <- data:
	case <-st.closed:
	}
}

// Read implements io.Reader, pulling bytes from received DATA frames.
func (st *Stream) Read(p []byte) (int, error) {
	if len(st.left) == 0 {
		select {
		case chunk, ok := <-st.readCh:
			if !ok {
				return 0, io.EOF
			}
			st.left = chunk
		case <-st.closed:
			return 0, st.closeErrOr(io.EOF)
		}
	}
	n := copy(p, st.left)
	st.left = st.left[n:]
	return n, nil
}

// Write implements io.Writer, splitting p into DATA frames no larger than
// frame.MaxDataLen.
func (st *Stream) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > frame.MaxDataLen {
			n = frame.MaxDataLen
		}
		if err := st.session.sendRaw(frame.TypeData, st.id, p[:n]); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

// Close sends CLOSE_STREAM and releases local state.
func (st *Stream) Close() error {
	var sendErr error
	st.closeOnce.Do(func() {
		payload := (&frame.CloseStreamPayload{Reason: 0}).Encode()
		sendErr = st.session.sendRaw(frame.TypeCloseStream, st.id, payload)
		st.session.mu.Lock()
		delete(st.session.streams, st.id)
		st.session.mu.Unlock()
		close(st.closed)
	})
	return sendErr
}

func (st *Stream) closeLocal(err error) {
	st.closeOnce.Do(func() {
		st.closeErr = err
		close(st.closed)
	})
}

func (st *Stream) closeErrOr(def error) error {
	if st.closeErr != nil {
		return st.closeErr
	}
	return def
}
