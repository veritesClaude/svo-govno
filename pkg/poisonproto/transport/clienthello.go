// Package transport implements L0 (ТЗ раздел 12): the TCP+TLS byte
// transport, including the server-side ClientHello peek that decides
// between real termination and fallback-site proxying (ТЗ §6.2–6.3).
//
// clienthello.go parses only the public wire *structure* of a TLS
// ClientHello (record/handshake framing, session_id, key_share) — no
// cryptography happens here. Input is untrusted (anyone can dial the
// server), so every length is bounds-checked and malformed input returns
// an error rather than panicking.
package transport

import (
	"encoding/binary"
	"errors"
	"io"
)

const (
	recTypeHandshake   = 0x16
	hsTypeClientHello  = 0x01
	extServerName      = 0x0000
	extKeyShare        = 0x0033
	groupX25519        = 29
	maxTLSRecordLen    = 16384 + 256 // generous slack over the RFC 8446 limit
	maxHandshakeMsgLen = 1 << 20     // sanity bound against a hostile declared length
)

var (
	ErrNotHandshake    = errors.New("transport: not a TLS handshake record")
	ErrNotClientHello  = errors.New("transport: handshake message is not a ClientHello")
	ErrMalformedHello  = errors.New("transport: malformed ClientHello")
	ErrNoX25519Share   = errors.New("transport: ClientHello has no X25519 key_share entry")
	ErrRecordTooLarge  = errors.New("transport: TLS record too large")
	ErrHandshakeTooBig = errors.New("transport: ClientHello handshake message too large")
)

// RawClientHello is the result of peeking a ClientHello off the wire: just
// enough structure to run the ТЗ §6.1 auth check before deciding whether
// to terminate TLS ourselves or splice the connection to a fallback site.
type RawClientHello struct {
	Raw          []byte // exact bytes of the ClientHello handshake message (type+len+body)
	SessionID    []byte // slice into Raw
	SessionIDOff int    // offset of SessionID within Raw
	ClientX25519 []byte // 32-byte X25519 public key from key_share, slice into Raw
	SNI          string
}

// ClientHelloAD returns Raw with the session_id field zeroed — the AEAD
// associated data the auth package binds the L1 token to (ТЗ §6.1). It
// never mutates Raw itself.
func (h *RawClientHello) ClientHelloAD() []byte {
	ad := make([]byte, len(h.Raw))
	copy(ad, h.Raw)
	for i := range ad[h.SessionIDOff : h.SessionIDOff+len(h.SessionID)] {
		ad[h.SessionIDOff+i] = 0
	}
	return ad
}

// readTLSRecord reads one TLS record header+payload from r.
func readTLSRecord(r io.Reader) (recordType byte, payload []byte, err error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	length := int(binary.BigEndian.Uint16(hdr[3:5]))
	if length > maxTLSRecordLen {
		return 0, nil, ErrRecordTooLarge
	}
	payload = make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return hdr[0], payload, nil
}

// PeekClientHello reads one or more TLS handshake records from r — just
// enough to assemble a complete ClientHello handshake message, which per
// ТЗ §5.5 is itself around 1800 bytes and may arrive as more than one TCP
// read, though normally as a single TLS record — and parses it. r should
// be a *recordingReader (see fallback.go) so the caller can replay the
// exact bytes consumed if the embedded token turns out invalid.
func PeekClientHello(r io.Reader) (*RawClientHello, error) {
	var msg []byte
	for {
		typ, payload, err := readTLSRecord(r)
		if err != nil {
			return nil, err
		}
		if typ != recTypeHandshake {
			return nil, ErrNotHandshake
		}
		msg = append(msg, payload...)
		if len(msg) < 4 {
			continue
		}
		declared := int(msg[1])<<16 | int(msg[2])<<8 | int(msg[3])
		if declared > maxHandshakeMsgLen {
			return nil, ErrHandshakeTooBig
		}
		if len(msg) >= 4+declared {
			msg = msg[:4+declared]
			break
		}
	}
	if msg[0] != hsTypeClientHello {
		return nil, ErrNotClientHello
	}
	return parseClientHello(msg)
}

func parseClientHello(msg []byte) (*RawClientHello, error) {
	// msg[0:4] = handshake header (type, 3-byte length), already validated.
	off := 4
	need := func(n int) error {
		if off+n > len(msg) {
			return ErrMalformedHello
		}
		return nil
	}

	if err := need(2 + 32 + 1); err != nil { // client_version + random + session_id len
		return nil, err
	}
	off += 2 + 32 // client_version, random

	sidLen := int(msg[off])
	off++
	sidOff := off
	if err := need(sidLen); err != nil {
		return nil, err
	}
	sessionID := msg[sidOff : sidOff+sidLen]
	off += sidLen

	if err := need(2); err != nil {
		return nil, err
	}
	csLen := int(binary.BigEndian.Uint16(msg[off : off+2]))
	off += 2
	if err := need(csLen); err != nil {
		return nil, err
	}
	off += csLen

	if err := need(1); err != nil {
		return nil, err
	}
	cmLen := int(msg[off])
	off++
	if err := need(cmLen); err != nil {
		return nil, err
	}
	off += cmLen

	result := &RawClientHello{Raw: msg, SessionID: sessionID, SessionIDOff: sidOff}

	if off == len(msg) {
		return nil, ErrNoX25519Share // no extensions at all -> definitely no key_share
	}
	if err := need(2); err != nil {
		return nil, err
	}
	extsLen := int(binary.BigEndian.Uint16(msg[off : off+2]))
	off += 2
	if err := need(extsLen); err != nil {
		return nil, err
	}
	extsEnd := off + extsLen

	foundKeyShare := false
	for off < extsEnd {
		if off+4 > extsEnd {
			return nil, ErrMalformedHello
		}
		extType := binary.BigEndian.Uint16(msg[off : off+2])
		extLen := int(binary.BigEndian.Uint16(msg[off+2 : off+4]))
		off += 4
		if off+extLen > extsEnd {
			return nil, ErrMalformedHello
		}
		extData := msg[off : off+extLen]
		off += extLen

		switch extType {
		case extServerName:
			if sni, ok := parseSNI(extData); ok {
				result.SNI = sni
			}
		case extKeyShare:
			if pub, ok := findX25519Share(extData); ok {
				result.ClientX25519 = pub
				foundKeyShare = true
			}
		}
	}

	if !foundKeyShare {
		return nil, ErrNoX25519Share
	}
	return result, nil
}

func parseSNI(ext []byte) (string, bool) {
	if len(ext) < 2 {
		return "", false
	}
	listLen := int(binary.BigEndian.Uint16(ext[0:2]))
	p := 2
	if p+listLen > len(ext) {
		return "", false
	}
	end := p + listLen
	for p+3 <= end {
		nameType := ext[p]
		nameLen := int(binary.BigEndian.Uint16(ext[p+1 : p+3]))
		p += 3
		if p+nameLen > end {
			return "", false
		}
		if nameType == 0 { // host_name
			return string(ext[p : p+nameLen]), true
		}
		p += nameLen
	}
	return "", false
}

func findX25519Share(ext []byte) ([]byte, bool) {
	if len(ext) < 2 {
		return nil, false
	}
	listLen := int(binary.BigEndian.Uint16(ext[0:2]))
	p := 2
	if p+listLen > len(ext) {
		return nil, false
	}
	end := p + listLen
	for p+4 <= end {
		group := binary.BigEndian.Uint16(ext[p : p+2])
		keLen := int(binary.BigEndian.Uint16(ext[p+2 : p+4]))
		p += 4
		if p+keLen > end {
			return nil, false
		}
		if group == groupX25519 && keLen == 32 {
			return ext[p : p+32], true
		}
		p += keLen
	}
	return nil, false
}
