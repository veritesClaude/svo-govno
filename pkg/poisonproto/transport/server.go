package transport

import (
	"context"
	"crypto/ecdh"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/veritesclaude/svo-govno/pkg/poisonproto/auth"
	"github.com/veritesclaude/svo-govno/pkg/poisonproto/crypto"
	"github.com/veritesclaude/svo-govno/pkg/poisonproto/session"
)

// ServerConfig holds everything AcceptRawConn needs to decide between
// real termination and fallback proxying, and to run the real path.
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

// ErrFallback is returned when a connection was handled by transparently
// proxying it to a fallback site (ТЗ §6.2) — there is no session to
// return, and the caller should just move on.
type ErrFallback struct{ Err error }

func (e *ErrFallback) Error() string {
	return fmt.Sprintf("transport: handled via fallback: %v", e.Err)
}
func (e *ErrFallback) Unwrap() error { return e.Err }

// AcceptRawConn peeks conn's ClientHello and either transparently proxies
// it to a fallback site (any failure: parse error, missing/invalid token,
// replay — all deliberately handled identically per ТЗ §6.2, returned as
// *ErrFallback) or terminates TLS 1.3 itself and completes the L2 Noise
// IK handshake (ТЗ §6.3, §7). The returned *crypto.Conn is not yet
// attached to any L3 session — see Server, which is what the pool (ТЗ
// §8.1) needs: every additional connection in the pool re-runs this exact
// same L1 authentication independently and must still end up joined to
// the right session rather than starting a new one each time.
func AcceptRawConn(conn net.Conn, cfg ServerConfig) (*crypto.Conn, uint64, error) {
	rr := newRecordingReader(conn)
	hello, err := PeekClientHello(rr)
	if err != nil {
		return nil, 0, &ErrFallback{Err: spliceToFallback(conn, rr.Consumed(), cfg.FallbackDial, "")}
	}

	fallback := func() (*crypto.Conn, uint64, error) {
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

	return crypto.NewConn(tlsConn, keys), userID, nil
}

// Server is a session registry on top of AcceptRawConn: ТЗ §8.1 has the
// client open a pool of connections per session, and §8.4 has it migrate
// by opening fresh ones when the pool dies — in both cases every
// additional connection must find and join the *same* session rather
// than starting a new one, and a session with no live connections stays
// registered for up to SessionIdleTTL (ТЗ §8.4: "до 60 секунд") in case
// migration is still in flight.
type Server struct {
	Config         ServerConfig
	SessionConfig  session.Config
	SessionIdleTTL time.Duration // default 60s

	mu       sync.Mutex
	sessions map[session.ID]*regEntry
}

type regEntry struct {
	sess   *session.Session
	userID uint64
}

// HandleConn runs AcceptRawConn on conn, then either creates a new
// session or joins the connection to one already registered under the
// attached ID — refusing to join if the ID matches a session that
// authenticated as a different user (defense in depth; session IDs are
// 16 random bytes, so this should never legitimately trigger).
func (srv *Server) HandleConn(conn net.Conn) (*session.Session, uint64, error) {
	c, userID, err := AcceptRawConn(conn, srv.Config)
	if err != nil {
		return nil, 0, err
	}

	id, err := session.ReadAttach(c)
	if err != nil {
		_ = c.Close()
		return nil, 0, fmt.Errorf("transport: read attach: %w", err)
	}

	srv.mu.Lock()
	if srv.sessions == nil {
		srv.sessions = make(map[session.ID]*regEntry)
	}
	entry := srv.sessions[id]
	srv.mu.Unlock()

	if entry != nil {
		if entry.userID != userID {
			_ = c.Close()
			return nil, 0, fmt.Errorf("transport: session %x belongs to a different user", id)
		}
		if err := session.CompleteAttach(c, id); err != nil {
			_ = c.Close()
			return nil, 0, err
		}
		entry.sess.AddConn(c)
		return entry.sess, userID, nil
	}

	if err := session.CompleteAttach(c, id); err != nil {
		_ = c.Close()
		return nil, 0, err
	}

	sessCfg := srv.SessionConfig
	if sessCfg.PoolMin == 0 {
		sessCfg = session.DefaultConfig()
	}
	newSess := session.NewFromAttached(id, c, false, sessCfg, nil)

	srv.mu.Lock()
	srv.sessions[id] = &regEntry{sess: newSess, userID: userID}
	srv.mu.Unlock()
	go srv.reapWhenIdle(newSess)

	return newSess, userID, nil
}

func (srv *Server) reapWhenIdle(s *session.Session) {
	ttl := srv.SessionIdleTTL
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	var idleSince time.Time
	for {
		select {
		case <-s.Done():
			srv.drop(s)
			return
		case <-ticker.C:
		}
		if s.LiveConnCount() == 0 {
			if idleSince.IsZero() {
				idleSince = time.Now()
			} else if time.Since(idleSince) > ttl {
				_ = s.Close()
				srv.drop(s)
				return
			}
		} else {
			idleSince = time.Time{}
		}
	}
}

func (srv *Server) drop(s *session.Session) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if e, ok := srv.sessions[s.ID()]; ok && e.sess == s {
		delete(srv.sessions, s.ID())
	}
}
