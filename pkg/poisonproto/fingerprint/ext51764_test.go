package fingerprint

import (
	"bytes"
	"testing"
	"time"
)

// variant 1 from ТЗ §5.7 (snapshots 1-3, Russian network).
const variant1Hex = "00cc04d679090f04d679090e08839a648c9b2d011308839a648c9b2d010708839a648c9b2d010c04d679090308839a648c9b2d010d04d679090c04d679090a0582df13021404d67909040582df13020104d679090504d679090808839a648c9b2d01080582df13020d04d679090b08839a648c9b2d01090582df13020608839a648c9b2d010a0582df13021304d679090604d67909090582df1302120582df13020f04d679090d08839a648c9b2d010b04d67909010582df13020e04d679090208839a648c9b2d011204d6790907"

func testParams() YandexAndroidParams {
	return YandexAndroidParams{
		Ext51764Prefixes:    []string{"d67909", "839a648c9b2d01", "82df1302"},
		Ext51764BaseVariant: variant1Hex,
		Ext51764RotateDays:  [2]int{3, 7},
		EchPayloadLens:      []int{144, 176},
	}
}

func TestParseExt51764Template(t *testing.T) {
	groups, order, err := parseExt51764Template(variant1Hex)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(order) != 3 {
		t.Fatalf("expected 3 groups, got %d: %v", len(order), order)
	}
	wantCounts := map[string]int{
		string([]byte{0xd6, 0x79, 0x09}):                         15,
		string([]byte{0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01}): 9,
		string([]byte{0x82, 0xdf, 0x13, 0x02}):                   8,
	}
	for prefix, want := range wantCounts {
		got := len(groups[prefix])
		if got != want {
			t.Errorf("group %x: got %d numbers, want %d", []byte(prefix), got, want)
		}
	}
}

func TestExt51764ValueDeterministicWithinPeriod(t *testing.T) {
	seed := []byte("device-seed-A")
	p := testParams()
	t0 := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)

	v1, err := Ext51764Value(seed, p, t0)
	if err != nil {
		t.Fatalf("Ext51764Value: %v", err)
	}
	v2, err := Ext51764Value(seed, p, t0.Add(24*time.Hour))
	if err != nil {
		t.Fatalf("Ext51764Value: %v", err)
	}
	if !bytes.Equal(v1, v2) {
		t.Errorf("value changed within 1 day, same device should be stable for its rotation period")
	}

	v3, err := Ext51764Value(seed, p, t0.Add(30*24*time.Hour))
	if err != nil {
		t.Fatalf("Ext51764Value: %v", err)
	}
	if bytes.Equal(v1, v3) {
		t.Errorf("value did not change after 30 days, rotation (max 7 days) should have advanced it")
	}
}

func TestExt51764ValueDiffersAcrossDevices(t *testing.T) {
	p := testParams()
	now := time.Now()
	v1, err := Ext51764Value([]byte("device-A"), p, now)
	if err != nil {
		t.Fatal(err)
	}
	v2, err := Ext51764Value([]byte("device-B"), p, now)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(v1, v2) {
		t.Errorf("two different devices produced identical ext51764 bytes")
	}
}

func TestExt51764ValueWellFormed(t *testing.T) {
	p := testParams()
	v, err := Ext51764Value([]byte("device-C"), p, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	groups, _, err := parseExt51764Template(hexEncode(v))
	if err != nil {
		t.Fatalf("generated value is not parseable by our own parser: %v", err)
	}
	if len(groups) == 0 {
		t.Fatalf("generated value has no groups")
	}
}

func hexEncode(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hexdigits[c>>4]
		out[i*2+1] = hexdigits[c&0xf]
	}
	return string(out)
}
