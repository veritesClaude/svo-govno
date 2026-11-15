package transport

import (
	"context"
	"crypto/ecdh"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/veritesclaude/svo-govno/pkg/poisonproto/auth"
	"github.com/veritesclaude/svo-govno/pkg/poisonproto/crypto"
	"github.com/veritesclaude/svo-govno/pkg/poisonproto/session"
)

// ServerConfig holds everything Accept needs to decide between real
// termination and fallback proxying, and to run the real path.
type ServerConfig struct {
	Verifier    *auth.Verifier
	NoiseStatic *ecdh.PrivateKey // same static key as Verifier's, reused for L2 (ТЗ §7)
	Cert        tls.Certificate
	// FallbackDial opens a connection to the real site a prober should see
	// for this SNI (empty sni means "no SNI parsed, use some default").
	FallbackDial func(sni string) (net.Conn, error)
	// UserAllowed, if set, is checked right after the token verifies: a
	// disabled/unknown user (ТЗ §15: "отключённые пользователи перестают
	// проходить авторизацию") is treated exactly like an invalid token —
	// fallback, not a distinguishable rejection (ТЗ §6.2).
	UserAllowed func(userID uint64) bool
}

// ErrFallback is returned by Accept when the connection was handled by
// transparently proxying it to a fallback site (ТЗ §6.2) — there is no
// session to return, and the caller should just move on.
type ErrFallback struct{ Err error }

func (e *ErrFallback) Error() string {
	return fmt.Sprintf("transport: handled via fallback: %v", e.Err)
}
func (e *ErrFallback) Unwrap() error { return e.Err }

// Accept peeks conn's ClientHello and either transparently proxies it to a
// fallback site (any failure: parse error, missing/invalid token, replay —
// all deliberately handled identically per ТЗ §6.2) or terminates TLS 1.3
// itself, completes the L2 Noise IK handshake, and attaches an L3 session
// (ТЗ §6.3, §7, §8.1). Blocks until the session is ready or the connection
// is handed off to fallback.
func Accept(conn net.Conn, cfg ServerConfig) (*session.Session, uint64, error) {
	rr := newRecordingReader(conn)
	hello, err := PeekClientHello(rr)
	if err != nil {
		return nil, 0, &ErrFallback{Err: spliceToFallback(conn, rr.Consumed(), cfg.FallbackDial, "")}
	}

	fallback := func() (*session.Session, uint64, error) {
		return nil, 0, &ErrFallback{Err: spliceToFallback(conn, rr.Consumed(), cfg.FallbackDial, hello.SNI)}
	}

	if len(hello.SessionID) != 32 {
		return fallback()
	}
	ephemeralPub, err := auth.ParseEphemeralPublicKey(hello.ClientX25519)
	if err != nil {
		return fallback()
	}
	var sessionID [32]byte
	copy(sessionID[:], hello.SessionID)

	userID, ok := cfg.Verifier.Verify(ephemeralPub, sessionID, hello.ClientHelloAD(), time.Now())
	if ok && cfg.UserAllowed != nil && !cfg.UserAllowed(userID) {
		ok = false
	}
	if !ok {
		return fallback()
	}

	replayed := &prefixConn{Conn: conn, prefix: rr.Consumed()}
	tlsConn := tls.Server(replayed, &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cfg.Cert},
	})
	if err := tlsConn.HandshakeContext(context.Background()); err != nil {
		return nil, 0, fmt.Errorf("transport: server TLS handshake: %w", err)
	}

	keys, err := crypto.Handshake(tlsConn, false, crypto.DHKeyFromECDH(cfg.NoiseStatic), nil)
	if err != nil {
		return nil, 0, fmt.Errorf("transport: L2 handshake: %w", err)
	}

	sess := session.New(session.ID{}, crypto.NewConn(tlsConn, keys), false)
	if err := sess.Attach(); err != nil {
		return nil, 0, fmt.Errorf("transport: L3 attach: %w", err)
	}
	return sess, userID, nil
}
