// poisonproto-server is the phase-1 prototype server (ТЗ §15, §17 п.1):
// it terminates PoisonProto connections authenticated via the L1 token and
// transparently proxies anything else to a configured fallback upstream.
//
// Scope note: this is the single-binary prototype for one node. Remnawave
// user sync, systemd packaging, and the install script are phase 5 (ТЗ
// §17 п.5) — see ROADMAP.md. User allow-listing here is a flat JSON file
// for now.
package main

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	"github.com/veritesclaude/svo-govno/pkg/poisonproto/auth"
	"github.com/veritesclaude/svo-govno/pkg/poisonproto/frame"
	"github.com/veritesclaude/svo-govno/pkg/poisonproto/session"
	"github.com/veritesclaude/svo-govno/pkg/poisonproto/transport"
)

func main() {
	var (
		listenAddr   = flag.String("listen", ":8443", "address to listen on")
		keyFile      = flag.String("keyfile", "server.key", "path to the server's static X25519 private key (base64); generated if missing")
		fallbackAddr = flag.String("fallback", "", "host:port of the real site to proxy unauthenticated/invalid connections to (ТЗ §6.2)")
		usersFile    = flag.String("users", "", "optional JSON file of allowed user IDs ([1,2,3]); if unset, all users with a valid token are allowed")
		ackWindow    = flag.Duration("auth-window", 120*time.Second, "clock-skew window for the L1 token (ТЗ §6.1)")
	)
	flag.Parse()

	if *fallbackAddr == "" {
		log.Fatal("--fallback is required (ТЗ §6.2: unauthenticated connections must see a real site)")
	}

	priv, pub, err := loadOrGenerateKey(*keyFile)
	if err != nil {
		log.Fatalf("server key: %v", err)
	}
	fmt.Printf("server_pubkey (base64, put this in the subscription config): %s\n",
		base64.StdEncoding.EncodeToString(pub.Bytes()))

	cert, err := transport.GenerateEphemeralCert()
	if err != nil {
		log.Fatalf("generate TLS cert: %v", err)
	}

	verifier := auth.NewVerifier(priv, *ackWindow)

	allowed, err := loadAllowedUsers(*usersFile)
	if err != nil {
		log.Fatalf("users file: %v", err)
	}

	ln, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("poisonproto-server listening on %s, fallback=%s", *listenAddr, *fallbackAddr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handleConn(conn, transport.ServerConfig{
			Verifier:    verifier,
			NoiseStatic: priv,
			Cert:        cert,
			FallbackDial: func(string) (net.Conn, error) {
				return net.Dial("tcp", *fallbackAddr)
			},
			UserAllowed: allowed,
		})
	}
}

func handleConn(conn net.Conn, cfg transport.ServerConfig) {
	sess, userID, err := transport.Accept(conn, cfg)
	if err != nil {
		var fb *transport.ErrFallback
		if errors.As(err, &fb) {
			log.Printf("%s: handled via fallback (%v)", conn.RemoteAddr(), fb.Err)
		} else {
			log.Printf("%s: accept failed: %v", conn.RemoteAddr(), err)
		}
		return
	}
	log.Printf("%s: session established for user %d", conn.RemoteAddr(), userID)

	go func() {
		if err := sess.Run(); err != nil {
			log.Printf("%s: session ended: %v", conn.RemoteAddr(), err)
		}
	}()

	for {
		st, err := sess.AcceptStream()
		if err != nil {
			return
		}
		go proxyStream(st)
	}
}

func proxyStream(st *session.Stream) {
	defer st.Close()
	if st.Network != frame.NetworkTCP {
		log.Printf("stream to %s: unsupported network %v (UDP is phase 3)", st.Addr, st.Network)
		return
	}
	upstream, err := net.DialTimeout("tcp", st.Addr, 10*time.Second)
	if err != nil {
		log.Printf("stream to %s: dial failed: %v", st.Addr, err)
		return
	}
	defer upstream.Close()

	done := make(chan struct{}, 2)
	go func() { io.Copy(upstream, st); done <- struct{}{} }()
	go func() { io.Copy(st, upstream); done <- struct{}{} }()
	<-done
}

func loadOrGenerateKey(path string) (*ecdh.PrivateKey, *ecdh.PublicKey, error) {
	if data, err := os.ReadFile(path); err == nil {
		raw, err := base64.StdEncoding.DecodeString(string(data))
		if err != nil {
			return nil, nil, fmt.Errorf("decode key file: %w", err)
		}
		priv, err := ecdh.X25519().NewPrivateKey(raw)
		if err != nil {
			return nil, nil, fmt.Errorf("parse key file: %w", err)
		}
		return priv, priv.PublicKey(), nil
	}

	priv, pub, err := auth.GenerateStaticKeyPair()
	if err != nil {
		return nil, nil, err
	}
	encoded := base64.StdEncoding.EncodeToString(priv.Bytes())
	if err := os.WriteFile(path, []byte(encoded), 0600); err != nil {
		return nil, nil, fmt.Errorf("write key file: %w", err)
	}
	log.Printf("generated new server static key at %s", path)
	return priv, pub, nil
}

func loadAllowedUsers(path string) (func(uint64) bool, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var ids []uint64
	if err := json.Unmarshal(data, &ids); err != nil {
		return nil, fmt.Errorf("parse users file: %w", err)
	}
	set := make(map[uint64]bool, len(ids))
	for _, id := range ids {
		set[id] = true
	}
	return func(id uint64) bool { return set[id] }, nil
}
