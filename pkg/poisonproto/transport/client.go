package transport

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/veritesclaude/svo-govno/pkg/poisonproto/auth"
	"github.com/veritesclaude/svo-govno/pkg/poisonproto/crypto"
	"github.com/veritesclaude/svo-govno/pkg/poisonproto/fingerprint"
	"github.com/veritesclaude/svo-govno/pkg/poisonproto/session"
)

// ClientConfig holds everything Dial needs to mask, authenticate, and
// establish one PoisonProto session (ТЗ §5, §6.1, §7, §8.1).
type ClientConfig struct {
	Addr            string // host:port to dial
	SNI             string // fallback site to present (ТЗ §6.4)
	ServerStaticPub *ecdh.PublicKey
	UserID          uint64
	DeviceSeed      []byte
	Fingerprint     fingerprint.YandexAndroidParams
	DialTimeout     time.Duration
	// Session configures the L3 pool/budget/ACK-timeout policy (ТЗ §8,
	// subscription config §14 "session" section). The zero value means
	// session.DefaultConfig().
	Session session.Config
}

func (c ClientConfig) sessionConfig() session.Config {
	if c.Session.PoolMin == 0 {
		return session.DefaultConfig()
	}
	return c.Session
}

// Dial opens a PoisonProto session: the first connection end to end (TCP,
// the yandex-android-masked TLS handshake with the ТЗ §6.1 token embedded
// in session_id, the L2 Noise IK handshake, and the L3 SESSION_ATTACH),
// then lets the session itself grow and maintain its connection pool (ТЗ
// §8.1) by calling back into dialRawConn for every additional connection
// it needs, including after migration (ТЗ §8.4).
func Dial(cfg ClientConfig) (*session.Session, error) {
	firstConn, err := dialRawConn(cfg)
	if err != nil {
		return nil, err
	}

	id, err := session.NewID()
	if err != nil {
		return nil, err
	}

	dialer := func() (*crypto.Conn, error) { return dialRawConn(cfg) }
	sess, err := session.New(id, firstConn, true, cfg.sessionConfig(), dialer)
	if err != nil {
		firstConn.Close()
		return nil, fmt.Errorf("transport: L3 attach: %w", err)
	}
	return sess, nil
}

// dialRawConn establishes one fully-masked, fully-authenticated L0-L2
// connection to cfg.Addr — everything up to (not including) the L3
// SESSION_ATTACH, so it can be reused both for a session's first
// connection and for every connection session.Dialer opens afterward.
func dialRawConn(cfg ClientConfig) (*crypto.Conn, error) {
	d := net.Dialer{Timeout: cfg.DialTimeout}
	raw, err := d.Dial("tcp", cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("transport: dial: %w", err)
	}
	c, err := handshake(raw, cfg)
	if err != nil {
		raw.Close()
		return nil, err
	}
	return c, nil
}

func handshake(raw net.Conn, cfg ClientConfig) (*crypto.Conn, error) {
	spec, err := fingerprint.BuildClientHelloSpec(cfg.DeviceSeed, time.Now(), cfg.Fingerprint, cfg.SNI)
	if err != nil {
		return nil, fmt.Errorf("transport: build ClientHello spec: %w", err)
	}

	uconn := utls.UClient(raw, &utls.Config{ServerName: cfg.SNI, InsecureSkipVerify: true}, utls.HelloCustom)
	if err := uconn.ApplyPreset(spec); err != nil {
		return nil, fmt.Errorf("transport: apply ClientHello preset: %w", err)
	}

	ephemeralPriv := uconn.HandshakeState.State13.KeyShareKeys.Ecdhe
	if ephemeralPriv == nil {
		return nil, fmt.Errorf("transport: no X25519 ephemeral key generated for ClientHello")
	}

	// Marshal once with session_id zeroed to get the AEAD associated data
	// (ТЗ §6.1), then again with the real token — see package fingerprint's
	// BuildClientHelloSpec doc comment for why both calls produce
	// byte-identical output outside the session_id span (GREASE and
	// GREASE-ECH randomness is generated once per extension instance and
	// cached, not re-rolled on re-marshal).
	uconn.HandshakeState.Hello.SessionId = make([]byte, 32)
	if err := uconn.MarshalClientHelloNoECH(); err != nil {
		return nil, fmt.Errorf("transport: marshal ClientHello (AD pass): %w", err)
	}
	ad := make([]byte, len(uconn.HandshakeState.Hello.Raw))
	copy(ad, uconn.HandshakeState.Hello.Raw)

	token, err := auth.ClientToken(ephemeralPriv, cfg.ServerStaticPub, cfg.UserID, ad, time.Now())
	if err != nil {
		return nil, fmt.Errorf("transport: compute auth token: %w", err)
	}
	uconn.HandshakeState.Hello.SessionId = token[:]
	if err := uconn.MarshalClientHelloNoECH(); err != nil {
		return nil, fmt.Errorf("transport: marshal ClientHello (final pass): %w", err)
	}

	if err := uconn.Handshake(); err != nil {
		return nil, fmt.Errorf("transport: TLS handshake: %w", err)
	}

	// L2: the client's Noise IK static keypair. ТЗ §7 reuses the same
	// server_pubkey the client already has for L1 as the server's Noise
	// static key (see package crypto's doc comment); the client's own
	// Noise static key is independent per-connection here in phase 1 (it
	// authenticates the server, not the client — client auth already
	// happened via the L1 token) so an ephemeral one is fine.
	clientNoiseStatic, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("transport: generate L2 static key: %w", err)
	}

	keys, err := crypto.Handshake(uconn, true, crypto.DHKeyFromECDH(clientNoiseStatic), crypto.RemoteStaticFromECDH(cfg.ServerStaticPub))
	if err != nil {
		return nil, fmt.Errorf("transport: L2 handshake: %w", err)
	}

	return crypto.NewConn(uconn, keys), nil
}
