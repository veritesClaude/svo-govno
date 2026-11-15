// Package frame implements the PoisonProto L3/L4 wire frame format.
//
// Frames are the plaintext unit carried inside the L2 (Noise) encrypted
// channel; see ТЗ раздел 10. Wire layout:
//
//	[type 1B][stream_id 4B][seq 8B][data_len 2B][data][padding]
//
// Padding length is implicit: it is whatever bytes remain in the plaintext
// buffer handed to Encode/Decode after data_len bytes of data, so it is
// never visible outside the encrypted L2 record.
package frame

import (
	"encoding/binary"
	"errors"
)

type Type byte

const (
	TypeData          Type = 0x01
	TypeACK           Type = 0x02
	TypeOpenStream    Type = 0x03
	TypeCloseStream   Type = 0x04
	TypeUDP           Type = 0x05
	TypePing          Type = 0x06
	TypePaddingOnly   Type = 0x07
	TypeRekey         Type = 0x08
	TypeSessionAttach Type = 0x09
	TypeWindowUpdate  Type = 0x0A
)

// HeaderLen is the fixed-size frame header: type(1) + stream_id(4) + seq(8) + data_len(2).
const HeaderLen = 1 + 4 + 8 + 2

// MaxDataLen is the largest payload the 2-byte data_len field can address.
const MaxDataLen = 0xFFFF

var (
	ErrTooShort  = errors.New("frame: buffer shorter than header")
	ErrTruncated = errors.New("frame: declared data_len exceeds buffer")
	ErrTooLarge  = errors.New("frame: data exceeds MaxDataLen")
)

// Frame is a decoded PoisonProto frame. Padding is kept separately from Data
// so callers can inspect/strip it without touching the payload.
type Frame struct {
	Type     Type
	StreamID uint32
	Seq      uint64
	Data     []byte
	Padding  []byte
}

// Encode serializes f into dst's backing buffer, growing as needed, and
// returns the resulting slice. Pass dst[:0] to reuse a buffer.
func Encode(dst []byte, f *Frame) ([]byte, error) {
	if len(f.Data) > MaxDataLen {
		return nil, ErrTooLarge
	}
	total := HeaderLen + len(f.Data) + len(f.Padding)
	if cap(dst) < total {
		dst = make([]byte, total)
	} else {
		dst = dst[:total]
	}
	dst[0] = byte(f.Type)
	binary.BigEndian.PutUint32(dst[1:5], f.StreamID)
	binary.BigEndian.PutUint64(dst[5:13], f.Seq)
	binary.BigEndian.PutUint16(dst[13:15], uint16(len(f.Data)))
	copy(dst[HeaderLen:], f.Data)
	copy(dst[HeaderLen+len(f.Data):], f.Padding)
	return dst, nil
}

// Decode parses a frame out of buf. The returned Frame's Data and Padding
// slices alias buf; copy them if buf will be reused.
func Decode(buf []byte) (*Frame, error) {
	if len(buf) < HeaderLen {
		return nil, ErrTooShort
	}
	dataLen := int(binary.BigEndian.Uint16(buf[13:15]))
	if HeaderLen+dataLen > len(buf) {
		return nil, ErrTruncated
	}
	f := &Frame{
		Type:     Type(buf[0]),
		StreamID: binary.BigEndian.Uint32(buf[1:5]),
		Seq:      binary.BigEndian.Uint64(buf[5:13]),
		Data:     buf[HeaderLen : HeaderLen+dataLen],
		Padding:  buf[HeaderLen+dataLen:],
	}
	return f, nil
}

func (t Type) String() string {
	switch t {
	case TypeData:
		return "DATA"
	case TypeACK:
		return "ACK"
	case TypeOpenStream:
		return "OPEN_STREAM"
	case TypeCloseStream:
		return "CLOSE_STREAM"
	case TypeUDP:
		return "UDP"
	case TypePing:
		return "PING"
	case TypePaddingOnly:
		return "PADDING_ONLY"
	case TypeRekey:
		return "REKEY"
	case TypeSessionAttach:
		return "SESSION_ATTACH"
	case TypeWindowUpdate:
		return "WINDOW_UPDATE"
	default:
		return "UNKNOWN"
	}
}
