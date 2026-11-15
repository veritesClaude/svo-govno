package auth

import (
	"crypto/ecdh"
	"crypto/rand"
	"testing"
	"time"
)

func genEphemeral(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ephemeral: %v", err)
	}
	return priv
}

func TestRoundTrip(t *testing.T) {
	serverPriv, serverPub, err := GenerateStaticKeyPair()
	if err != nil {
		t.Fatalf("GenerateStaticKeyPair: %v", err)
	}
	clientEph := genEphemeral(t)
	ad := []byte("fake-clienthello-bytes-with-session-id-zeroed")
	now := time.Now()

	tok, err := ClientToken(clientEph, serverPub, 42, ad, now)
	if err != nil {
		t.Fatalf("ClientToken: %v", err)
	}

	v := NewVerifier(serverPriv, 120*time.Second)
	uid, ok := v.Verify(clientEph.PublicKey(), tok, ad, now)
	if !ok {
		t.Fatalf("Verify: expected ok=true")
	}
	if uid != 42 {
		t.Fatalf("Verify: userID = %d, want 42", uid)
	}
}

func TestTamperedAD(t *testing.T) {
	serverPriv, serverPub, _ := GenerateStaticKeyPair()
	clientEph := genEphemeral(t)
	ad := []byte("fake-clienthello-bytes-with-session-id-zeroed")
	now := time.Now()

	tok, err := ClientToken(clientEph, serverPub, 42, ad, now)
	if err != nil {
		t.Fatalf("ClientToken: %v", err)
	}

	tamperedAD := append([]byte{}, ad...)
	tamperedAD[0] ^= 0x01

	v := NewVerifier(serverPriv, 120*time.Second)
	if _, ok := v.Verify(clientEph.PublicKey(), tok, tamperedAD, now); ok {
		t.Fatalf("Verify: expected failure on tampered AD")
	}
}

func TestWrongServerKey(t *testing.T) {
	_, serverPub, _ := GenerateStaticKeyPair()
	otherPriv, _, _ := GenerateStaticKeyPair()
	clientEph := genEphemeral(t)
	ad := []byte("fake-clienthello-bytes-with-session-id-zeroed")
	now := time.Now()

	tok, err := ClientToken(clientEph, serverPub, 42, ad, now)
	if err != nil {
		t.Fatalf("ClientToken: %v", err)
	}

	v := NewVerifier(otherPriv, 120*time.Second)
	if _, ok := v.Verify(clientEph.PublicKey(), tok, ad, now); ok {
		t.Fatalf("Verify: expected failure with wrong server key")
	}
}

func TestClockSkewRejected(t *testing.T) {
	serverPriv, serverPub, _ := GenerateStaticKeyPair()
	clientEph := genEphemeral(t)
	ad := []byte("fake-clienthello-bytes-with-session-id-zeroed")
	issued := time.Now()

	tok, err := ClientToken(clientEph, serverPub, 42, ad, issued)
	if err != nil {
		t.Fatalf("ClientToken: %v", err)
	}

	v := NewVerifier(serverPriv, 120*time.Second)
	later := issued.Add(10 * time.Minute)
	if _, ok := v.Verify(clientEph.PublicKey(), tok, ad, later); ok {
		t.Fatalf("Verify: expected failure outside clock-skew window")
	}
}

func TestReplayRejected(t *testing.T) {
	serverPriv, serverPub, _ := GenerateStaticKeyPair()
	clientEph := genEphemeral(t)
	ad := []byte("fake-clienthello-bytes-with-session-id-zeroed")
	now := time.Now()

	tok, err := ClientToken(clientEph, serverPub, 42, ad, now)
	if err != nil {
		t.Fatalf("ClientToken: %v", err)
	}

	v := NewVerifier(serverPriv, 120*time.Second)
	if _, ok := v.Verify(clientEph.PublicKey(), tok, ad, now); !ok {
		t.Fatalf("Verify: first use expected to succeed")
	}
	if _, ok := v.Verify(clientEph.PublicKey(), tok, ad, now); ok {
		t.Fatalf("Verify: replay of the same token expected to fail")
	}
}

func TestGarbageSessionID(t *testing.T) {
	serverPriv, _, _ := GenerateStaticKeyPair()
	clientEph := genEphemeral(t)
	ad := []byte("fake-clienthello-bytes-with-session-id-zeroed")
	now := time.Now()

	var garbage [32]byte
	if _, err := rand.Read(garbage[:]); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	v := NewVerifier(serverPriv, 120*time.Second)
	if _, ok := v.Verify(clientEph.PublicKey(), garbage, ad, now); ok {
		t.Fatalf("Verify: expected failure on garbage session id")
	}
}
