// Package auth implements the L1 token-in-session_id authorization scheme
// (ТЗ §6.1–§6.2): a Reality-style check that lets the server tell a real
// client from an unauthenticated prober using only the bytes already
// present in the ClientHello, before any TLS state is spent on the
// connection.
package auth

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const hkdfInfo = "poisonproto-token-v1"

// sessionID layout (32 bytes total, ТЗ §6.1):
//
//	[0:3]   random padding (cosmetic only, not authenticated)
//	[3:32]  AEAD ciphertext = Seal(plaintext, ad=clientHelloAD), 29 bytes
//	        = 13 bytes plaintext (version 1B + unixtime 4B + userID 8B) + 16 byte tag
//
// The AEAD key is derived per-handshake via HKDF-SHA256 over the X25519
// ECDH shared secret between the client's ephemeral key_share key and the
// server's static key. Because that shared secret (and therefore the
// derived key) is unique to this one handshake — a fresh ephemeral key is
// generated for every ClientHello — sealing with an all-zero 12-byte nonce
// under ChaCha20-Poly1305 never reuses a (key, nonce) pair, which is the
// only thing that would make a fixed nonce unsafe.
const (
	tokenPadLen  = 3
	plaintextLen = 1 + 4 + 8 // version + unixtime + userID
	cipherLen    = plaintextLen + chacha20poly1305.Overhead
)

var zeroNonce [chacha20poly1305.NonceSize]byte

const tokenVersion byte = 1

var (
	ErrBadToken = errors.New("auth: invalid token")
)

// GenerateStaticKeyPair creates a new server-side X25519 static keypair.
func GenerateStaticKeyPair() (priv *ecdh.PrivateKey, pub *ecdh.PublicKey, err error) {
	priv, err = ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return priv, priv.PublicKey(), nil
}

// ParsePublicKey decodes a 32-byte raw X25519 public key.
func ParsePublicKey(raw []byte) (*ecdh.PublicKey, error) {
	return ecdh.X25519().NewPublicKey(raw)
}

// ParseEphemeralPublicKey decodes the 32 raw bytes of an X25519 public key
// as found in a ClientHello's key_share extension for the X25519 group.
func ParseEphemeralPublicKey(raw []byte) (*ecdh.PublicKey, error) {
	return ParsePublicKey(raw)
}

func deriveKey(shared []byte) []byte {
	r := hkdf.New(sha256.New, shared, nil, []byte(hkdfInfo))
	key := make([]byte, chacha20poly1305.KeySize)
	// hkdf.New's Reader never returns a short read followed by a non-nil
	// error for a length within the RFC 5869 expansion limit, so a single
	// ReadFull-style read is enough; io.ReadFull not used to avoid the
	// extra import for one call site.
	n := 0
	for n < len(key) {
		m, err := r.Read(key[n:])
		if err != nil {
			return nil
		}
		n += m
	}
	return key
}

// ClientToken computes the 32-byte value to place in the TLS session_id.
func ClientToken(ephemeralPriv *ecdh.PrivateKey, serverPub *ecdh.PublicKey, userID uint64, clientHelloAD []byte, now time.Time) ([32]byte, error) {
	var out [32]byte
	shared, err := ephemeralPriv.ECDH(serverPub)
	if err != nil {
		return out, err
	}
	key := deriveKey(shared)
	if key == nil {
		return out, ErrBadToken
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return out, err
	}

	plaintext := make([]byte, plaintextLen)
	plaintext[0] = tokenVersion
	binary.BigEndian.PutUint32(plaintext[1:5], uint32(now.Unix()))
	binary.BigEndian.PutUint64(plaintext[5:13], userID)

	ciphertext := aead.Seal(nil, zeroNonce[:], plaintext, clientHelloAD)
	if len(ciphertext) != cipherLen {
		return out, ErrBadToken
	}
	if _, err := rand.Read(out[:tokenPadLen]); err != nil {
		return out, err
	}
	copy(out[tokenPadLen:], ciphertext)
	return out, nil
}

// replayEntry is the expiry time of a consumed token.
type replayEntry = time.Time

// Verifier owns the server static private key and the replay cache.
type Verifier struct {
	priv   *ecdh.PrivateKey
	window time.Duration

	mu     sync.Mutex
	seen   map[[cipherLen]byte]replayEntry
	lastGC time.Time
}

// NewVerifier constructs a Verifier. window is the allowed clock skew
// (ТЗ §6.1 default ±120s).
func NewVerifier(priv *ecdh.PrivateKey, window time.Duration) *Verifier {
	return &Verifier{
		priv:   priv,
		window: window,
		seen:   make(map[[cipherLen]byte]replayEntry),
	}
}

// Verify checks sessionID against the token scheme. ok=false for any
// failure (bad tag, clock skew, replay, malformed input) — deliberately
// indistinguishable from the outside so callers can fall through to
// fallback-site proxying without leaking which check failed (ТЗ §6.2/§6.3).
func (v *Verifier) Verify(ephemeralPub *ecdh.PublicKey, sessionID [32]byte, clientHelloAD []byte, now time.Time) (userID uint64, ok bool) {
	shared, err := v.priv.ECDH(ephemeralPub)
	if err != nil {
		return 0, false
	}
	key := deriveKey(shared)
	if key == nil {
		return 0, false
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return 0, false
	}

	var ciphertext [cipherLen]byte
	copy(ciphertext[:], sessionID[tokenPadLen:])

	plaintext, err := aead.Open(nil, zeroNonce[:], ciphertext[:], clientHelloAD)
	if err != nil {
		return 0, false
	}
	if len(plaintext) != plaintextLen || plaintext[0] != tokenVersion {
		return 0, false
	}

	ts := int64(binary.BigEndian.Uint32(plaintext[1:5]))
	skew := now.Unix() - ts
	if skew < 0 {
		skew = -skew
	}
	if skew > int64(v.window/time.Second) {
		return 0, false
	}
	uid := binary.BigEndian.Uint64(plaintext[5:13])

	if !v.recordIfNew(ciphertext, now) {
		return 0, false
	}
	return uid, true
}

// recordIfNew returns true (and remembers the token) the first time this
// exact ciphertext is seen within the replay window, false on any repeat.
func (v *Verifier) recordIfNew(ciphertext [cipherLen]byte, now time.Time) bool {
	v.mu.Lock()
	defer v.mu.Unlock()

	if now.Sub(v.lastGC) > v.window {
		for k, exp := range v.seen {
			if now.After(exp) {
				delete(v.seen, k)
			}
		}
		v.lastGC = now
	}

	if exp, exists := v.seen[ciphertext]; exists && now.Before(exp) {
		return false
	}
	v.seen[ciphertext] = now.Add(2 * v.window)
	return true
}
