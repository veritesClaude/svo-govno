package session

import (
	"crypto/ecdh"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"

	"github.com/veritesclaude/svo-govno/pkg/poisonproto/crypto"
	"github.com/veritesclaude/svo-govno/pkg/poisonproto/frame"
)

func newPairedSessions(t *testing.T) (client, server *Session) {
	t.Helper()

	serverPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	c1, c2 := net.Pipe()

	type result struct {
		keys *crypto.TransportKeys
		err  error
	}
	clientRes := make(chan result, 1)
	serverRes := make(chan result, 1)

	go func() {
		keys, err := crypto.Handshake(c1, true, crypto.DHKeyFromECDH(clientPriv), crypto.RemoteStaticFromECDH(serverPriv.PublicKey()))
		clientRes <- result{keys, err}
	}()
	go func() {
		keys, err := crypto.Handshake(c2, false, crypto.DHKeyFromECDH(serverPriv), nil)
		serverRes <- result{keys, err}
	}()

	cr := <-clientRes
	sr := <-serverRes
	if cr.err != nil {
		t.Fatalf("client handshake: %v", cr.err)
	}
	if sr.err != nil {
		t.Fatalf("server handshake: %v", sr.err)
	}

	id, err := NewID()
	if err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		PoolMin: 1, PoolMax: 1,
		BudgetMin: 1 << 30, BudgetMax: 1<<30 + 1,
		Adaptive:      false,
		AckTimeoutMin: 300 * time.Millisecond,
		AckTimeoutMax: 500 * time.Millisecond,
	}

	type newResult struct {
		sess *Session
		err  error
	}
	clientNew := make(chan newResult, 1)
	serverNew := make(chan newResult, 1)
	go func() {
		s, err := New(id, crypto.NewConn(c1, cr.keys), true, cfg, nil)
		clientNew <- newResult{s, err}
	}()
	go func() {
		s, err := New(ID{}, crypto.NewConn(c2, sr.keys), false, cfg, nil)
		serverNew <- newResult{s, err}
	}()

	cn := <-clientNew
	if cn.err != nil {
		t.Fatalf("client New: %v", cn.err)
	}
	sn := <-serverNew
	if sn.err != nil {
		t.Fatalf("server New: %v", sn.err)
	}
	client, server = cn.sess, sn.sess

	if client.ID() != server.ID() {
		t.Fatalf("session ID mismatch after attach: %x != %x", client.ID(), server.ID())
	}

	return client, server
}

func TestStreamDataRoundTrip(t *testing.T) {
	client, server := newPairedSessions(t)
	defer client.Close()
	defer server.Close()

	cst, err := client.OpenStream(frame.NetworkTCP, "example.invalid:443")
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}

	sst, err := server.AcceptStream()
	if err != nil {
		t.Fatalf("AcceptStream: %v", err)
	}
	if sst.Addr != "example.invalid:443" || sst.Network != frame.NetworkTCP {
		t.Fatalf("unexpected accepted stream: %+v", sst)
	}

	msg := []byte("hello over poisonproto")
	done := make(chan error, 1)
	go func() {
		_, err := cst.Write(msg)
		done <- err
	}()

	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(sst, buf); err != nil {
		t.Fatalf("server read: %v", err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("got %q want %q", buf, msg)
	}
	if err := <-done; err != nil {
		t.Fatalf("client write: %v", err)
	}

	// reverse direction
	reply := []byte("ack from server")
	go func() { _, _ = sst.Write(reply) }()
	buf2 := make([]byte, len(reply))
	if _, err := io.ReadFull(cst, buf2); err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(buf2) != string(reply) {
		t.Fatalf("got %q want %q", buf2, reply)
	}
}

func TestStreamClose(t *testing.T) {
	client, server := newPairedSessions(t)
	defer client.Close()
	defer server.Close()

	cst, err := client.OpenStream(frame.NetworkTCP, "x:1")
	if err != nil {
		t.Fatal(err)
	}
	sst, err := server.AcceptStream()
	if err != nil {
		t.Fatal(err)
	}

	if err := cst.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		_, err := sst.Read(make([]byte, 1))
		errCh <- err
	}()
	select {
	case err := <-errCh:
		if err != io.EOF {
			t.Fatalf("expected io.EOF after peer close, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for close propagation")
	}
}

func TestPingEcho(t *testing.T) {
	client, server := newPairedSessions(t)
	defer client.Close()
	defer server.Close()
	_ = server

	if err := client.sendRaw(frame.TypePing, 0, []byte("nonce")); err != nil {
		t.Fatalf("send ping: %v", err)
	}
	// The echo comes back through client's own Run() loop as a PING frame;
	// since Run() only dispatches internally in phase 1 (no public PING
	// callback yet), this test just checks the round trip doesn't hang or
	// error the session — exercised indirectly via a subsequent stream op.
	time.Sleep(50 * time.Millisecond)
	select {
	case <-client.Done():
		t.Fatal("session died handling PING")
	default:
	}
}
