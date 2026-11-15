// Package crypto implements L2 (ТЗ раздел 7): Noise IK running inside the
// already-established L1 TLS byte stream. It only wires together vetted
// primitives (X25519, ChaCha20-Poly1305, SHA-256 via flynn/noise) per ТЗ
// раздел 3, принцип 1 — no cipher or handshake logic is invented here.
//
// Static key reuse: the same X25519 static keypair used for the L1 token
// scheme (package auth) is reused as the Noise IK static key. This is safe
// because Noise's own transcript hash is seeded with the protocol name
// ("Noise_IK_25519_ChaChaPoly_SHA256", via noise.HandshakeIK/NewCipherSuite),
// which domain-separates its key schedule from the unrelated HKDF info
// string the auth package uses over the same ECDH shared secret. ТЗ §7
// leaves "тот же или отдельный ключ" open; this is the deliberate choice,
// picked to match the single server_pubkey field in the subscription
// config (ТЗ раздел 14).
package crypto

import (
	"crypto/ecdh"
	"fmt"
	"io"

	"github.com/flynn/noise"
)

// CipherSuite is the fixed set of primitives for the L2 channel.
var CipherSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)

// DHKeyFromECDH converts a stdlib X25519 keypair into the raw-byte shape
// flynn/noise expects.
func DHKeyFromECDH(priv *ecdh.PrivateKey) noise.DHKey {
	return noise.DHKey{
		Private: priv.Bytes(),
		Public:  priv.PublicKey().Bytes(),
	}
}

// RemoteStaticFromECDH extracts the raw public key bytes flynn/noise wants
// for Config.PeerStatic.
func RemoteStaticFromECDH(pub *ecdh.PublicKey) []byte {
	return pub.Bytes()
}

// TransportKeys holds the two independent CipherStates a completed IK
// handshake yields: one per direction. They are NOT interchangeable —
// Send must only be used for messages this side originates, Recv only for
// messages read from the peer.
type TransportKeys struct {
	Send *noise.CipherState
	Recv *noise.CipherState
}

// Handshake runs one side of Noise_IK_25519_ChaChaPoly_SHA256 over rw and
// returns the resulting transport keys. initiator=true is the client side;
// it must already know the server's static public key (remoteStatic) —
// exactly the server_pubkey already present in the client's subscription
// config, which is what the IK pattern requires of the initiator.
//
// rw is expected to carry only this handshake's two messages: callers must
// frame them (see Conn in conn.go) so Handshake doesn't need to know about
// record boundaries itself. Message framing is identical to the data-phase
// record framing (2-byte big-endian length prefix) for simplicity.
func Handshake(rw io.ReadWriter, initiator bool, localStatic noise.DHKey, remoteStatic []byte) (*TransportKeys, error) {
	cfg := noise.Config{
		CipherSuite:   CipherSuite,
		Pattern:       noise.HandshakeIK,
		Initiator:     initiator,
		StaticKeypair: localStatic,
	}
	if initiator {
		cfg.PeerStatic = remoteStatic
	}
	hs, err := noise.NewHandshakeState(cfg)
	if err != nil {
		return nil, fmt.Errorf("crypto: new handshake state: %w", err)
	}

	if initiator {
		msg, _, _, err := hs.WriteMessage(nil, nil)
		if err != nil {
			return nil, fmt.Errorf("crypto: write msg1: %w", err)
		}
		if err := writeFramed(rw, msg); err != nil {
			return nil, fmt.Errorf("crypto: send msg1: %w", err)
		}

		reply, err := readFramed(rw, maxHandshakeMsg)
		if err != nil {
			return nil, fmt.Errorf("crypto: recv msg2: %w", err)
		}
		// flynn/noise's Split() always returns (c1, c2) in the same order
		// regardless of role; per the Noise spec the initiator encrypts
		// with c1 and decrypts with c2, so csSend/csRecv below are *not*
		// swapped — the responder branch below swaps them instead.
		_, csSend, csRecv, err := hs.ReadMessage(nil, reply)
		if err != nil {
			return nil, fmt.Errorf("crypto: read msg2: %w", err)
		}
		return &TransportKeys{Send: csSend, Recv: csRecv}, nil
	}

	msg1, err := readFramed(rw, maxHandshakeMsg)
	if err != nil {
		return nil, fmt.Errorf("crypto: recv msg1: %w", err)
	}
	if _, _, _, err := hs.ReadMessage(nil, msg1); err != nil {
		return nil, fmt.Errorf("crypto: read msg1: %w", err)
	}

	msg2, csRecv, csSend, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("crypto: write msg2: %w", err)
	}
	if err := writeFramed(rw, msg2); err != nil {
		return nil, fmt.Errorf("crypto: send msg2: %w", err)
	}
	return &TransportKeys{Send: csSend, Recv: csRecv}, nil
}
