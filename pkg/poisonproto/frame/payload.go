package frame

import (
	"encoding/binary"
	"errors"
)

// Structured bodies carried in Frame.Data for specific frame types.
// These are separate from the frame header codec above so the session/mux
// layers can stay agnostic of wire details beyond their own payload.

var ErrBadPayload = errors.New("frame: malformed payload")

// AckPayload is the Data body of a TypeACK frame: a cumulative ACK plus a
// small set of selectively-acknowledged sequence numbers (ТЗ 8.3).
type AckPayload struct {
	Cumulative uint64
	Selective  []uint64
}

func (a *AckPayload) Encode() []byte {
	buf := make([]byte, 8+2+8*len(a.Selective))
	binary.BigEndian.PutUint64(buf[0:8], a.Cumulative)
	binary.BigEndian.PutUint16(buf[8:10], uint16(len(a.Selective)))
	for i, s := range a.Selective {
		binary.BigEndian.PutUint64(buf[10+8*i:18+8*i], s)
	}
	return buf
}

func DecodeAckPayload(buf []byte) (*AckPayload, error) {
	if len(buf) < 10 {
		return nil, ErrBadPayload
	}
	n := int(binary.BigEndian.Uint16(buf[8:10]))
	if len(buf) < 10+8*n {
		return nil, ErrBadPayload
	}
	a := &AckPayload{Cumulative: binary.BigEndian.Uint64(buf[0:8])}
	a.Selective = make([]uint64, n)
	for i := 0; i < n; i++ {
		a.Selective[i] = binary.BigEndian.Uint64(buf[10+8*i : 18+8*i])
	}
	return a, nil
}

// Network protocols a stream can carry (ТЗ 8.4 / OPEN_STREAM).
type Network byte

const (
	NetworkTCP Network = 1
	NetworkUDP Network = 2
)

// OpenStreamPayload is the Data body of a TypeOpenStream frame.
type OpenStreamPayload struct {
	Network Network
	Addr    string // host:port
}

func (o *OpenStreamPayload) Encode() []byte {
	addr := []byte(o.Addr)
	buf := make([]byte, 1+2+len(addr))
	buf[0] = byte(o.Network)
	binary.BigEndian.PutUint16(buf[1:3], uint16(len(addr)))
	copy(buf[3:], addr)
	return buf
}

func DecodeOpenStreamPayload(buf []byte) (*OpenStreamPayload, error) {
	if len(buf) < 3 {
		return nil, ErrBadPayload
	}
	n := int(binary.BigEndian.Uint16(buf[1:3]))
	if len(buf) < 3+n {
		return nil, ErrBadPayload
	}
	return &OpenStreamPayload{
		Network: Network(buf[0]),
		Addr:    string(buf[3 : 3+n]),
	}, nil
}

// WindowUpdatePayload is the Data body of a TypeWindowUpdate frame: the
// additional number of bytes the sender may now transmit on this stream.
type WindowUpdatePayload struct {
	Delta uint32
}

func (w *WindowUpdatePayload) Encode() []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, w.Delta)
	return buf
}

func DecodeWindowUpdatePayload(buf []byte) (*WindowUpdatePayload, error) {
	if len(buf) < 4 {
		return nil, ErrBadPayload
	}
	return &WindowUpdatePayload{Delta: binary.BigEndian.Uint32(buf[0:4])}, nil
}

// CloseStreamPayload is the Data body of a TypeCloseStream frame.
type CloseStreamPayload struct {
	Reason byte // 0 = normal
}

func (c *CloseStreamPayload) Encode() []byte { return []byte{c.Reason} }

func DecodeCloseStreamPayload(buf []byte) (*CloseStreamPayload, error) {
	if len(buf) < 1 {
		return nil, ErrBadPayload
	}
	return &CloseStreamPayload{Reason: buf[0]}, nil
}
