// poisonproto-client is the phase-1 prototype client (ТЗ §16, §17 п.1): it
// reads a subscription config (ТЗ раздел 14), dials the first configured
// server with the yandex-android-masked handshake, and forwards one local
// TCP listener's connections to one fixed remote target through the
// resulting session.
//
// Scope note: this stands in for the real sing-box/libbox integration
// (phase 5, ТЗ §16) — it exercises the same L0–L3 code the real client
// outbound will use, without the Android/Flutter UI around it.
package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/veritesclaude/svo-govno/pkg/poisonproto/auth"
	"github.com/veritesclaude/svo-govno/pkg/poisonproto/config"
	"github.com/veritesclaude/svo-govno/pkg/poisonproto/fingerprint"
	"github.com/veritesclaude/svo-govno/pkg/poisonproto/frame"
	"github.com/veritesclaude/svo-govno/pkg/poisonproto/transport"
)

func main() {
	var (
		configPath     = flag.String("config", "subscription.json", "subscription config path (ТЗ раздел 14)")
		serverID       = flag.String("server", "", "server id to use; defaults to the first entry")
		listenAddr     = flag.String("listen", "127.0.0.1:1080", "local address to accept plain TCP connections on")
		target         = flag.String("target", "", "remote host:port every accepted connection is forwarded to, through the tunnel")
		deviceSeedFile = flag.String("device-seed", "poisonproto-device.seed", "path to this device's stable fingerprint seed (ТЗ §5.7); generated if missing")
	)
	flag.Parse()

	if *target == "" {
		log.Fatal("--target is required (e.g. --target example.com:443)")
	}

	cfgFile, err := os.Open(*configPath)
	if err != nil {
		log.Fatalf("open config: %v", err)
	}
	cfg, err := config.Parse(cfgFile)
	cfgFile.Close()
	if err != nil {
		log.Fatalf("parse config: %v", err)
	}

	srv := pickServer(cfg, *serverID)
	log.Printf("using server %q (%s:%d)", srv.ID, srv.Addr, srv.Port)

	serverPub, err := decodeServerPubkey(srv.ServerPubkey)
	if err != nil {
		log.Fatalf("server_pubkey: %v", err)
	}

	deviceSeed, err := loadOrCreateDeviceSeed(*deviceSeedFile)
	if err != nil {
		log.Fatalf("device seed: %v", err)
	}

	userID := userIDFromToken(cfg.UserTokenID)

	ln, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("forwarding %s -> %s through poisonproto", *listenAddr, *target)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handleLocalConn(conn, *target, transport.ClientConfig{
			Addr:            net.JoinHostPort(srv.Addr, strconv.Itoa(srv.Port)),
			SNI:             pickFallbackSNI(srv),
			ServerStaticPub: serverPub,
			UserID:          userID,
			DeviceSeed:      deviceSeed,
			Fingerprint:     fingerprintParamsFromConfig(cfg),
			DialTimeout:     10 * time.Second,
		})
	}
}

func handleLocalConn(local net.Conn, target string, cfg transport.ClientConfig) {
	defer local.Close()

	sess, err := transport.Dial(cfg)
	if err != nil {
		log.Printf("dial poisonproto: %v", err)
		return
	}
	go func() {
		if err := sess.Run(); err != nil {
			log.Printf("session ended: %v", err)
		}
	}()
	defer sess.Close()

	st, err := sess.OpenStream(frame.NetworkTCP, target)
	if err != nil {
		log.Printf("open stream to %s: %v", target, err)
		return
	}
	defer st.Close()

	done := make(chan struct{}, 2)
	go func() { io.Copy(st, local); done <- struct{}{} }()
	go func() { io.Copy(local, st); done <- struct{}{} }()
	<-done
}

func pickServer(cfg *config.Config, id string) *config.Server {
	if id == "" {
		return &cfg.Servers[0]
	}
	for i := range cfg.Servers {
		if cfg.Servers[i].ID == id {
			return &cfg.Servers[i]
		}
	}
	log.Fatalf("server %q not found in config", id)
	return nil
}

func pickFallbackSNI(srv *config.Server) string {
	if len(srv.FallbackSNI) == 0 {
		log.Fatalf("server %q has no fallback_sni configured", srv.ID)
	}
	return srv.FallbackSNI[0]
}

func decodeServerPubkey(b64 string) (*ecdh.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	return auth.ParsePublicKey(raw)
}

func loadOrCreateDeviceSeed(path string) ([]byte, error) {
	if data, err := os.ReadFile(path); err == nil {
		raw, err := base64.StdEncoding.DecodeString(string(data))
		if err == nil && len(raw) == 32 {
			return raw, nil
		}
	}
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(seed)), 0600); err != nil {
		return nil, err
	}
	return seed, nil
}

// userIDFromToken derives the short per-user id from the subscription's
// user_token_id (ТЗ раздел 14): numeric as-is, otherwise the first 8 bytes
// of SHA-256 (ТЗ §15 describes deriving it from the account UUID server
// side — any deterministic, collision-resistant mapping works as long as
// client and server agree, and SHA-256 is an approved primitive, ТЗ §3.1).
func userIDFromToken(token string) uint64 {
	if n, err := strconv.ParseUint(token, 10, 64); err == nil {
		return n
	}
	h := sha256.Sum256([]byte(token))
	return binary.BigEndian.Uint64(h[:8])
}

func fingerprintParamsFromConfig(cfg *config.Config) fingerprint.YandexAndroidParams {
	return fingerprint.YandexAndroidParams{
		Ext51764Prefixes:    cfg.Fingerprint.Ext51764.Prefixes,
		Ext51764BaseVariant: cfg.Fingerprint.Ext51764.BaseVariant,
		Ext51764RotateDays:  cfg.Fingerprint.Ext51764.RotateDays,
		EchPayloadLens:      cfg.Fingerprint.EchPayloadLens,
	}
}
