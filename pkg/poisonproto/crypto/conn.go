package crypto

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

// Wire framing for both handshake messages and data-phase records: a
// 2-byte big-endian length prefix followed by that many bytes. This lives
// below L3 (package frame): what's inside a record here is either a raw
// Noise handshake message, or — once the handshake is done — a Noise
// ciphertext whose plaintext is an L3 frame (package frame).
const (
	lenPrefixSize    = 2
	maxHandshakeMsg  = 4096           // generous; real IK messages are a few hundred bytes
	MaxRecordPayload = 1<<16 - 1 - 16 // leaves room for the 16-byte Poly1305 tag within the 2-byte length
)

var ErrRecordTooLarge = errors.New("crypto: record exceeds MaxRecordPayload")

func writeFramed(w io.Writer, payload []byte) error {
	if len(payload) > 1<<16-1 {
		return ErrRecordTooLarge
	}
	var hdr [lenPrefixSize]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func readFramed(r io.Reader, max int) ([]byte, error) {
	var hdr [lenPrefixSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n > max {
		return nil, ErrRecordTooLarge
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// RekeyBytes / RekeyInterval implement ТЗ §7: "Каждые 64 МБ или 10 минут —
// смена ключей (REKEY)", independently per direction.
const (
	RekeyBytes    = 64 * 1024 * 1024
	RekeyInterval = 10 * time.Minute
)

// Conn is the L2 record layer: it turns an io.ReadWriter carrying the L1
// TLS byte stream into Seal/Open of discrete L3-frame-sized plaintexts.
// It does not itself decide *when* to rekey — package session owns that
// policy (it has to coordinate emitting/observing a REKEY frame on the
// wire) — it only exposes ShouldRekeySend/RekeySend/RekeyRecv so session
// can drive it.
type Conn struct {
	rw   io.ReadWriter
	keys *TransportKeys

	sendBytes uint64
	sendSince time.Time
	recvBytes uint64
	recvSince time.Time
}

func NewConn(rw io.ReadWriter, keys *TransportKeys) *Conn {
	now := time.Now()
	return &Conn{rw: rw, keys: keys, sendSince: now, recvSince: now}
}

// Seal encrypts one plaintext L3 frame and writes it as a length-prefixed
// record. ad is additional authenticated data (empty is fine; session may
// pass something like the session ID to bind records to a session).
func (c *Conn) Seal(plaintext, ad []byte) error {
	if len(plaintext) > MaxRecordPayload {
		return ErrRecordTooLarge
	}
	ct, err := c.keys.Send.Encrypt(nil, ad, plaintext)
	if err != nil {
		return fmt.Errorf("crypto: encrypt: %w", err)
	}
	if err := writeFramed(c.rw, ct); err != nil {
		return err
	}
	c.sendBytes += uint64(len(plaintext))
	return nil
}

// Open reads one length-prefixed record and decrypts it.
func (c *Conn) Open(ad []byte) ([]byte, error) {
	ct, err := readFramed(c.rw, 1<<16-1)
	if err != nil {
		return nil, err
	}
	pt, err := c.keys.Recv.Decrypt(nil, ad, ct)
	if err != nil {
		return nil, fmt.Errorf("crypto: decrypt: %w", err)
	}
	c.recvBytes += uint64(len(pt))
	return pt, nil
}

// ShouldRekeySend reports whether this side has sent enough data, or
// enough time has passed, that it should emit a REKEY frame and rotate its
// send key (ТЗ §7).
func (c *Conn) ShouldRekeySend() bool {
	return c.sendBytes >= RekeyBytes || time.Since(c.sendSince) >= RekeyInterval
}

// RekeySend rotates the send CipherState. Call this immediately after
// sending a REKEY frame, so the peer — which rotates its matching Recv
// key immediately after processing that frame — stays in lockstep without
// any additional handshake (Noise's Rekey() is deterministic given the
// current key, so both sides derive the same new key independently).
func (c *Conn) RekeySend() {
	c.keys.Send.Rekey()
	c.sendBytes = 0
	c.sendSince = time.Now()
}

// RekeyRecv rotates the recv CipherState; call immediately after observing
// an inbound REKEY frame, before decrypting the next record.
func (c *Conn) RekeyRecv() {
	c.keys.Recv.Rekey()
	c.recvBytes = 0
	c.recvSince = time.Now()
}
