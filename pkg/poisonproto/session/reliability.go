// Reliability (ТЗ §8.3): every frame gets a session-global, monotonic
// sequence number (assigned in Session.sendRaw), regardless of type —
// that lets the receiver detect gaps generically and build a cumulative
// ACK. Only DATA frames are tracked in `unacked` for retransmission;
// losing a control frame (PING, ACK itself, OPEN_STREAM, CLOSE_STREAM,
// REKEY, WINDOW_UPDATE) is either self-healing (the next one supersedes
// it) or — for REKEY specifically — simply dooms that one connection,
// which the pool already treats as an ordinary dead connection. Extending
// retransmission to OPEN_STREAM/CLOSE_STREAM is a reasonable phase-3
// follow-up, not required by §8.3's literal wording.
package session

import (
	"sort"
	"time"

	"github.com/veritesclaude/svo-govno/pkg/poisonproto/frame"
)

// pendingFrame is one DATA frame sent but not yet ACKed.
type pendingFrame struct {
	seq           uint64
	streamID      uint32
	data          []byte
	connID        uint64
	sentAt        time.Time // zero until the first successful send attempt
	retransmitted bool
}

// noteReceived folds seq into the receive-side gap tracker and reports
// whether this is the first time it's been seen — callers use that to
// decide whether to actually act on (e.g. deliver to a stream) or just
// silently re-ACK a frame, since a retransmitted DATA frame can legitimately
// arrive twice (the original wasn't lost, only its ACK was).
func (s *Session) noteReceived(seq uint64) (isNew bool) {
	s.relMu.Lock()
	defer s.relMu.Unlock()

	if seq <= s.cumulative {
		return false
	}
	if _, ok := s.recvSeen[seq]; ok {
		return false
	}
	s.recvSeen[seq] = struct{}{}
	for {
		if _, ok := s.recvSeen[s.cumulative+1]; !ok {
			break
		}
		delete(s.recvSeen, s.cumulative+1)
		s.cumulative++
	}
	return true
}

// trySend attempts to put buf (the already-encoded frame for pf) on the
// wire via some live pool connection, trying a few distinct connections
// before giving up. On success it records which connection and when, for
// the retransmit timer; on total failure pf is left exactly as it was
// (zero sentAt), so the next retransmitLoop tick — which treats a zero
// sentAt as always overdue — retries it almost immediately once the pool
// recovers (ТЗ §8.4).
func (s *Session) trySend(pf *pendingFrame, buf []byte) bool {
	tried := make(map[uint64]bool, 4)
	for i := 0; i < 4; i++ {
		pc := s.pickConn(tried)
		if pc == nil {
			return false
		}
		tried[pc.id] = true
		if err := s.sendOn(pc, buf, len(pf.data)); err != nil {
			continue
		}
		s.relMu.Lock()
		pf.connID = pc.id
		pf.sentAt = time.Now()
		s.relMu.Unlock()
		return true
	}
	return false
}

// handleAck applies an incoming ACK: anything it covers (cumulatively or
// selectively) stops being retransmitted, and a same-transmission sample
// feeds the RTT estimator (Karn's algorithm: a retransmitted frame's ACK
// can't be attributed to a specific send, so it's excluded).
func (s *Session) handleAck(f *frame.Frame) {
	ack, err := frame.DecodeAckPayload(f.Data)
	if err != nil {
		return
	}
	now := time.Now()
	selective := make(map[uint64]bool, len(ack.Selective))
	for _, sq := range ack.Selective {
		selective[sq] = true
	}

	s.relMu.Lock()
	defer s.relMu.Unlock()
	for seq, pf := range s.unacked {
		if seq > ack.Cumulative && !selective[seq] {
			continue
		}
		if !pf.retransmitted && !pf.sentAt.IsZero() {
			s.rtt.sample(now.Sub(pf.sentAt))
		}
		delete(s.unacked, seq)
	}
}

// ackLoop periodically reports what's been received so far, so the sender
// can detect loss. It only sends when there's something new to say.
func (s *Session) ackLoop() {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	var lastCum uint64
	var lastSelCount int
	for {
		select {
		case <-s.closed:
			return
		case <-ticker.C:
		}

		s.relMu.Lock()
		cum := s.cumulative
		sel := make([]uint64, 0, len(s.recvSeen))
		for seq := range s.recvSeen {
			sel = append(sel, seq)
		}
		s.relMu.Unlock()

		if cum == lastCum && len(sel) == lastSelCount && len(sel) == 0 {
			continue
		}
		sort.Slice(sel, func(i, j int) bool { return sel[i] < sel[j] })

		payload := (&frame.AckPayload{Cumulative: cum, Selective: sel}).Encode()
		if err := s.sendRaw(frame.TypeACK, 0, payload); err == nil {
			lastCum, lastSelCount = cum, len(sel)
		}
	}
}

// retransmitLoop implements ТЗ §8.3's core rule: "Нет ACK за 300–500 мс
// (зависит от RTT) → соединение считается замёрзшим, неподтверждённые
// кадры переотправляются по другому соединению пула, замёрзшее
// закрывается." A connection with any overdue frame is evicted wholesale
// (not just that one frame) — freezing is a property DPI inflicts on a
// whole TCP connection, not individual records.
func (s *Session) retransmitLoop() {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-s.closed:
			return
		case <-ticker.C:
		}
		s.checkRetransmits()
	}
}

func (s *Session) checkRetransmits() {
	timeout := s.rtt.timeout()
	now := time.Now()

	s.relMu.Lock()
	var expired []*pendingFrame
	connsToEvict := make(map[uint64]bool)
	for _, pf := range s.unacked {
		if pf.sentAt.IsZero() || now.Sub(pf.sentAt) > timeout {
			expired = append(expired, pf)
			if !pf.sentAt.IsZero() {
				connsToEvict[pf.connID] = true
			}
		}
	}
	s.relMu.Unlock()

	for connID := range connsToEvict {
		if pc := s.getConn(connID); pc != nil {
			s.evictConnection(pc)
		}
	}

	for _, pf := range expired {
		s.relMu.Lock()
		_, stillPending := s.unacked[pf.seq]
		s.relMu.Unlock()
		if !stillPending {
			continue // ACKed or otherwise resolved between the scan above and now
		}
		buf, err := frame.Encode(nil, &frame.Frame{Type: frame.TypeData, StreamID: pf.streamID, Seq: pf.seq, Data: pf.data})
		if err != nil {
			continue
		}
		pf.retransmitted = true
		s.trySend(pf, buf)
	}
}
