// Package fingerprint builds uTLS ClientHelloSpecs that reproduce the
// Yandex Browser (Android) TLS fingerprint captured in ТЗ §5, so PoisonProto
// connections are classified as ordinary Yandex Browser traffic rather than
// a VPN.
package fingerprint

import (
	"crypto/rand"
	"time"

	utls "github.com/refraction-networking/utls"
)

// YandexAndroidParams carries the subscription-config-driven knobs for the
// yandex-android profile (ТЗ §3 принцип 3: masking parameters live in config,
// not code).
type YandexAndroidParams struct {
	Ext51764Prefixes    []string // ТЗ §5.7 group prefixes, hex, e.g. "d67909"
	Ext51764BaseVariant string   // hex template ("вариант 1"), see ext51764.go
	Ext51764RotateDays  [2]int   // [min,max] days a device keeps one ext51764 value
	EchPayloadLens      []int    // GREASE ECH total wire payload lengths to pick from, e.g. [144,176]
}

// BuildClientHelloSpec builds the yandex-android ClientHelloSpec for one
// connection attempt. deviceSeed is a stable per-device secret (used only to
// derive the slow-rotating ext51764 value, ТЗ §5.7); sni is the fallback
// site's hostname for this connection.
//
// GREASE values (cipher, groups, the two boundary extensions, TLS versions)
// are intentionally left as utls.GREASE_PLACEHOLDER: uTLS regenerates them
// randomly, consistently, and distinctly (ТЗ §5.5) every time ApplyPreset
// runs on a fresh *utls.UConn, which is exactly "a new random GREASE set per
// connection" without this package having to touch uTLS's internal grease
// state. signature_algorithms GREASE is the one exception — uTLS v1.8.2
// does not re-grease that extension on ApplyPreset, so we roll our own
// per-call RFC 8701-shaped value here to avoid sending the same literal
// 0x0a0a on every connection.
//
// IMPORTANT: the ТЗ §6.1 auth token goes in the TLS session_id, but uTLS
// v1.8.2's ApplyPreset ignores ClientHelloSpec.GetSessionID for the
// HelloCustom path and always assigns a fresh random session_id. Callers
// must therefore set `uconn.HandshakeState.Hello.SessionId` themselves,
// after ApplyPreset and before Handshake(); this package only builds the
// spec and has no access to the UConn.
func BuildClientHelloSpec(deviceSeed []byte, now time.Time, p YandexAndroidParams, sni string) (*utls.ClientHelloSpec, error) {
	spec := &utls.ClientHelloSpec{
		CipherSuites: []uint16{
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
		},
		CompressionMethods: []uint8{0},
	}

	ext51764, err := Ext51764Value(deviceSeed, p, now)
	if err != nil {
		return nil, err
	}

	echPayloadLen, err := pickEchPayloadLen(p.EchPayloadLens)
	if err != nil {
		return nil, err
	}

	sigAlgoGrease, err := randomGreaseValue()
	if err != nil {
		return nil, err
	}

	// middle holds the 17 ТЗ §5.5 extensions (PSK resumption, out of scope
	// here, would be spliced in right before the closing GREASE later).
	middle := []utls.TLSExtension{
		&utls.SNIExtension{ServerName: sni},
		&utls.ExtendedMasterSecretExtension{},
		&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
		&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
			utls.CurveID(utls.GREASE_PLACEHOLDER),
			utls.X25519MLKEM768,
			utls.X25519,
			utls.CurveP256,
			utls.CurveP384,
		}},
		&utls.SupportedPointsExtension{SupportedPoints: []uint8{0}},
		&utls.SessionTicketExtension{},
		&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
		&utls.StatusRequestExtension{},
		&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
			sigAlgoGrease,
			0x0904, // mldsa44 (PQ signature, no named const in utls v1.8.2 yet)
			0x0905, // mldsa65
			0x0906, // mldsa87
			utls.ECDSAWithP256AndSHA256,
			utls.PSSWithSHA256,
			utls.PKCS1WithSHA256,
			utls.ECDSAWithP384AndSHA384,
			utls.PSSWithSHA384,
			utls.PKCS1WithSHA384,
			utls.PSSWithSHA512,
			utls.PKCS1WithSHA512,
		}},
		&utls.SCTExtension{},
		&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
			{Group: utls.CurveID(utls.GREASE_PLACEHOLDER), Data: []byte{0}},
			{Group: utls.X25519MLKEM768},
			{Group: utls.X25519},
		}},
		&utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}},
		&utls.SupportedVersionsExtension{Versions: []uint16{
			utls.GREASE_PLACEHOLDER,
			utls.VersionTLS13,
			utls.VersionTLS12,
		}},
		&utls.UtlsCompressCertExtension{Algorithms: []utls.CertCompressionAlgo{utls.CertCompressionBrotli}},
		&utls.ApplicationSettingsExtensionNew{SupportedProtocols: []string{"h2"}},
		greaseECHExtension(echPayloadLen),
		&utls.GenericExtension{Id: 0xCA34, Data: ext51764},
	}

	exts := make([]utls.TLSExtension, 0, len(middle)+2)
	exts = append(exts, &utls.UtlsGREASEExtension{}) // filled in as extension1 by ApplyPreset
	exts = append(exts, middle...)
	exts = append(exts, &utls.UtlsGREASEExtension{}) // filled in as extension2 by ApplyPreset

	// ShuffleChromeTLSExtensions never moves a *UtlsGREASEExtension, so the
	// two boundary markers above stay first/last exactly as ТЗ §5.5 requires
	// while everything else gets a fresh random order per connection.
	spec.Extensions = utls.ShuffleChromeTLSExtensions(exts)

	return spec, nil
}

// greaseECHExtension builds the GREASE ECH extension per ТЗ §5.6: AEAD
// pinned to AES-128-GCM (matches a device with hardware AES, avoiding the
// known uTLS tell where GREASE ECH's cipher disagrees with the client's real
// AEAD preference) and a total wire payload length of wireLen bytes.
// CandidatePayloadLens is documented as pre-AEAD-tag ("if 0, picks
// 128(+16=144)"), so we subtract the 16-byte Poly1305/GCM tag here.
func greaseECHExtension(wireLen int) *utls.GREASEEncryptedClientHelloExtension {
	const aeadTagLen = 16
	return &utls.GREASEEncryptedClientHelloExtension{
		CandidateCipherSuites: []utls.HPKESymmetricCipherSuite{
			{KdfId: 0x0001, AeadId: 0x0001}, // HKDF-SHA256 / AES-128-GCM
		},
		CandidatePayloadLens: []uint16{uint16(wireLen - aeadTagLen)},
	}
}

func pickEchPayloadLen(lens []int) (int, error) {
	if len(lens) == 0 {
		return 144, nil
	}
	idx, err := randomIndex(len(lens))
	if err != nil {
		return 0, err
	}
	return lens[idx], nil
}

// randomGreaseValue produces an RFC 8701-shaped GREASE value (0xωaωa), used
// for the one extension (signature_algorithms) that uTLS v1.8.2 does not
// re-grease on its own.
func randomGreaseValue() (utls.SignatureScheme, error) {
	var b [1]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	v := uint16(b[0]&0xf0) | 0x0a
	v |= v << 8
	return utls.SignatureScheme(v), nil
}

func randomIndex(n int) (int, error) {
	if n <= 1 {
		return 0, nil
	}
	var b [1]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return int(b[0]) % n, nil
}
