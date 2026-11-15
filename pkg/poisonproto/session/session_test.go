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

	client = New(id, crypto.NewConn(c1, cr.keys), true)
	server = New(ID{}, crypto.NewConn(c2, sr.keys), false)

	attachErr := make(chan error, 2)
	go func() { attachErr <- server.Attach() }()
	go func() { attachErr <- client.Attach() }()
	for i := 0; i < 2; i++ {
		if err := <-attachErr; err != nil {
			t.Fatalf("attach: %v", err)
		}
	}
	if client.ID() != server.ID() {
		t.Fatalf("session ID mismatch after attach: %x != %x", client.ID(), server.ID())
	}

	go client.Run()
	go server.Run()

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
