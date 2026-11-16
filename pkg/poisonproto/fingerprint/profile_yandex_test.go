package fingerprint

import (
	"net"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

func buildAppliedSpec(t *testing.T) (*utls.ClientHelloSpec, *utls.UConn) {
	t.Helper()
	spec, err := BuildClientHelloSpec([]byte("device-seed"), time.Now(), testParams(), "example.com")
	if err != nil {
		t.Fatalf("BuildClientHelloSpec: %v", err)
	}
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() { clientConn.Close(); serverConn.Close() })

	uconn := utls.UClient(clientConn, &utls.Config{ServerName: "example.com", InsecureSkipVerify: true}, utls.HelloCustom)
	if err := uconn.ApplyPreset(spec); err != nil {
		t.Fatalf("ApplyPreset: %v", err)
	}
	return spec, uconn
}

func TestCipherSuiteOrder(t *testing.T) {
	spec, _ := buildAppliedSpec(t)
	want := []uint16{
		utls.GREASE_PLACEHOLDER,
		utls.TLS_AES_128_GCM_SHA256,
		utls.TLS_AES_256_GCM_SHA384,
		utls.TLS_CHACHA20_POLY1305_SHA256,
		utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		utls.TLS_RSA_WITH_AES_128_CBC_SHA,
		utls.TLS_RSA_WITH_AES_256_CBC_SHA,
	}
	if len(spec.CipherSuites) != len(want) {
		t.Fatalf("got %d cipher suites, want %d", len(spec.CipherSuites), len(want))
	}
	for i := range want {
		if i == 0 {
			continue // GREASE value itself is randomized by uTLS at ApplyPreset time
		}
		if spec.CipherSuites[i] != want[i] {
			t.Errorf("cipher[%d] = %#04x, want %#04x", i, spec.CipherSuites[i], want[i])
		}
	}
}

func TestBoundaryGreaseExtensions(t *testing.T) {
	_, uconn := buildAppliedSpec(t)
	exts := uconn.Extensions
	first, ok1 := exts[0].(*utls.UtlsGREASEExtension)
	last, ok2 := exts[len(exts)-1].(*utls.UtlsGREASEExtension)
	if !ok1 || !ok2 {
		t.Fatalf("first/last extension are not GREASE: %T / %T", exts[0], exts[len(exts)-1])
	}
	if first.Value == last.Value {
		t.Errorf("boundary GREASE extensions share the same value %#04x, want two distinct values", first.Value)
	}
	if len(first.Body) != 0 {
		t.Errorf("first GREASE extension body = %v, want empty (Chrome convention)", first.Body)
	}
	if len(last.Body) != 1 || last.Body[0] != 0 {
		t.Errorf("last GREASE extension body = %v, want [0] (Chrome convention)", last.Body)
	}
}

func TestExtensionSetComplete(t *testing.T) {
	_, uconn := buildAppliedSpec(t)
	wantIDs := map[uint16]bool{
		0: true, 23: true, 65281: true, 10: true, 11: true, 35: true,
		16: true, 5: true, 13: true, 18: true, 51: true, 45: true,
		43: true, 27: true, 17613: true, 65037: true, 0xCA34: true,
	}
	got := map[uint16]int{}
	greaseCount := 0
	for _, e := range uconn.Extensions {
		switch ext := e.(type) {
		case *utls.UtlsGREASEExtension:
			greaseCount++
		case *utls.SNIExtension:
			got[0]++
		case *utls.ExtendedMasterSecretExtension:
			got[23]++
		case *utls.RenegotiationInfoExtension:
			got[65281]++
		case *utls.SupportedCurvesExtension:
			got[10]++
		case *utls.SupportedPointsExtension:
			got[11]++
		case *utls.SessionTicketExtension:
			got[35]++
		case *utls.ALPNExtension:
			got[16]++
		case *utls.StatusRequestExtension:
			got[5]++
		case *utls.SignatureAlgorithmsExtension:
			got[13]++
		case *utls.SCTExtension:
			got[18]++
		case *utls.KeyShareExtension:
			got[51]++
		case *utls.PSKKeyExchangeModesExtension:
			got[45]++
		case *utls.SupportedVersionsExtension:
			got[43]++
		case *utls.UtlsCompressCertExtension:
			got[27]++
		case *utls.ApplicationSettingsExtensionNew:
			got[17613]++
		case *utls.GREASEEncryptedClientHelloExtension:
			got[65037]++
		case *utls.GenericExtension:
			got[ext.Id]++
		default:
			t.Errorf("unexpected extension type %T", e)
		}
	}
	if greaseCount != 2 {
		t.Errorf("got %d GREASE extensions, want 2", greaseCount)
	}
	for id := range wantIDs {
		if got[id] != 1 {
			t.Errorf("extension id %#04x: got count %d, want 1", id, got[id])
		}
	}
}

func TestKeyShareOrder(t *testing.T) {
	_, uconn := buildAppliedSpec(t)
	for _, e := range uconn.Extensions {
		ks, ok := e.(*utls.KeyShareExtension)
		if !ok {
			continue
		}
		if len(ks.KeyShares) != 3 {
			t.Fatalf("got %d key shares, want 3", len(ks.KeyShares))
		}
		if ks.KeyShares[1].Group != utls.X25519MLKEM768 {
			t.Errorf("key_share[1] group = %v, want X25519MLKEM768", ks.KeyShares[1].Group)
		}
		if ks.KeyShares[2].Group != utls.X25519 {
			t.Errorf("key_share[2] group = %v, want X25519", ks.KeyShares[2].Group)
		}
		// RFC 8701 GREASE values are 0x?A?A with both bytes equal (0x0A0A,
		// 0x1A1A, ... 0xFAFA); the placeholder (0x0A0A) is itself one of the
		// 16 possible values, so checking "!= placeholder" is wrong — it
		// would spuriously fail ~1/16 of the time when ApplyPreset's random
		// substitution happens to land back on 0x0A0A.
		g := uint16(ks.KeyShares[0].Group)
		if hi, lo := g>>8, g&0xff; hi != lo || lo&0x0f != 0x0a {
			t.Errorf("key_share[0] group %#04x is not a valid GREASE value", g)
		}
		return
	}
	t.Fatalf("no KeyShareExtension found")
}

func TestGreaseECHPayloadLen(t *testing.T) {
	const aeadTagLen = 16
	seen := map[int]bool{}
	for i := 0; i < 200; i++ {
		spec, err := BuildClientHelloSpec([]byte("device-seed"), time.Now(), testParams(), "example.com")
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range spec.Extensions {
			ech, ok := e.(*utls.GREASEEncryptedClientHelloExtension)
			if !ok {
				continue
			}
			if len(ech.CandidatePayloadLens) != 1 {
				t.Fatalf("got %d candidate payload lens, want 1", len(ech.CandidatePayloadLens))
			}
			total := int(ech.CandidatePayloadLens[0]) + aeadTagLen
			seen[total] = true
		}
	}
	for total := range seen {
		if total != 144 && total != 176 {
			t.Errorf("observed ECH total payload length %d, want one of {144,176}", total)
		}
	}
	if len(seen) < 2 {
		t.Errorf("only observed %v across 200 samples, want both 144 and 176 to appear", seen)
	}
}
