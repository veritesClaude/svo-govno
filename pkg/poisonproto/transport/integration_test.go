package transport

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"

	"github.com/veritesclaude/svo-govno/pkg/poisonproto/auth"
	"github.com/veritesclaude/svo-govno/pkg/poisonproto/fingerprint"
	"github.com/veritesclaude/svo-govno/pkg/poisonproto/frame"
)

const testBaseVariant = "00cc04d679090f04d679090e08839a648c9b2d011308839a648c9b2d010708839a648c9b2d010c04d679090308839a648c9b2d010d04d679090c04d679090a0582df13021404d67909040582df13020104d679090504d679090808839a648c9b2d01080582df13020d04d679090b08839a648c9b2d01090582df13020608839a648c9b2d010a0582df13021304d679090604d67909090582df1302120582df13020f04d679090d08839a648c9b2d010b04d67909010582df13020e04d679090208839a648c9b2d011204d6790907"

func testFingerprintParams() fingerprint.YandexAndroidParams {
	return fingerprint.YandexAndroidParams{
		Ext51764Prefixes:    []string{"d67909", "839a648c9b2d01", "82df1302"},
		Ext51764BaseVariant: testBaseVariant,
		Ext51764RotateDays:  [2]int{3, 7},
		EchPayloadLens:      []int{144, 176},
	}
}

// startFakeFallback runs a tiny TCP server that records every byte it
// receives on each connection and writes back a fixed canned response —
// standing in for a real fallback website in tests.
func startFakeFallback(t *testing.T, response []byte) (addr string, received func() []byte) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	var got []byte
	gotCh := make(chan []byte, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 65536)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, _ := conn.Read(buf)
		got = append([]byte(nil), buf[:n]...)
		gotCh <- got
		_, _ = conn.Write(response)
	}()

	return ln.Addr().String(), func() []byte {
		select {
		case b := <-gotCh:
			return b
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for fallback to receive data")
			return nil
		}
	}
}

func TestDialAcceptEndToEnd(t *testing.T) {
	serverPriv, serverPub, err := auth.GenerateStaticKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := GenerateEphemeralCert()
	if err != nil {
		t.Fatal(err)
	}
	verifier := auth.NewVerifier(serverPriv, 120*time.Second)

	fallbackAddr, _ := startFakeFallback(t, []byte("should not be used"))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	type acceptResult struct {
		userID uint64
		err    error
	}
	resCh := make(chan acceptResult, 1)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			resCh <- acceptResult{0, err}
			return
		}
		sess, userID, err := Accept(conn, ServerConfig{
			Verifier:    verifier,
			NoiseStatic: serverPriv,
			Cert:        cert,
			FallbackDial: func(string) (net.Conn, error) {
				return net.Dial("tcp", fallbackAddr)
			},
		})
		if err != nil {
			resCh <- acceptResult{0, err}
			return
		}
		go sess.Run()

		st, err := sess.AcceptStream()
		if err != nil {
			resCh <- acceptResult{0, err}
			return
		}
		buf := make([]byte, 5)
		if _, err := io.ReadFull(st, buf); err != nil {
			resCh <- acceptResult{0, err}
			return
		}
		if _, err := st.Write([]byte("world")); err != nil {
			resCh <- acceptResult{0, err}
			return
		}
		resCh <- acceptResult{userID, nil}
	}()

	deviceSeed := make([]byte, 32)
	rand.Read(deviceSeed)

	clientSess, err := Dial(ClientConfig{
		Addr:            ln.Addr().String(),
		SNI:             "example.invalid",
		ServerStaticPub: serverPub,
		UserID:          42,
		DeviceSeed:      deviceSeed,
		Fingerprint:     testFingerprintParams(),
		DialTimeout:     5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	go clientSess.Run()

	st, err := clientSess.OpenStream(frame.NetworkTCP, "irrelevant:1")
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	if _, err := st.Write([]byte("hello")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(st, buf); err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(buf) != "world" {
		t.Fatalf("got %q want %q", buf, "world")
	}

	select {
	case res := <-resCh:
		if res.err != nil {
			t.Fatalf("server side: %v", res.err)
		}
		if res.userID != 42 {
			t.Fatalf("userID: got %d want 42", res.userID)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server goroutine")
	}
}

func TestAcceptFallsBackOnInvalidToken(t *testing.T) {
	serverPriv, _, err := auth.GenerateStaticKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := GenerateEphemeralCert()
	if err != nil {
		t.Fatal(err)
	}
	verifier := auth.NewVerifier(serverPriv, 120*time.Second)

	canned := []byte("this is the real fallback site's response")
	fallbackAddr, received := startFakeFallback(t, canned)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		_, _, _ = Accept(conn, ServerConfig{
			Verifier:    verifier,
			NoiseStatic: serverPriv,
			Cert:        cert,
			FallbackDial: func(string) (net.Conn, error) {
				return net.Dial("tcp", fallbackAddr)
			},
		})
	}()

	// A well-formed yandex-android ClientHello, but with a random
	// (non-token) session_id, is exactly what a prober or a copy-pasted
	// old handshake looks like: it must be proxied to the real fallback
	// site byte for byte (ТЗ §6.2), not rejected.
	var randomSessionID [32]byte
	rand.Read(randomSessionID[:])
	record, _ := buildRealClientHello(t, randomSessionID)

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	if _, err := client.Write(record); err != nil {
		t.Fatalf("client write: %v", err)
	}

	gotByFallback := received()
	if !bytes.Equal(gotByFallback, record) {
		t.Fatalf("fallback did not receive the exact ClientHello bytes:\ngot  %x\nwant %x", gotByFallback, record)
	}

	client.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, len(canned))
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatalf("client read fallback response: %v", err)
	}
	if !bytes.Equal(buf, canned) {
		t.Fatalf("client got %q, want the real fallback's %q", buf, canned)
	}
}
