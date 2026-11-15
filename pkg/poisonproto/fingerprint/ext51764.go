package fingerprint

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/rand/v2"
	"sort"
	"time"
)

// Ext51764Value implements the ТЗ §5.7 generator for the Yandex 0xCA34
// extension payload: it derives, purely from deviceSeed and the current
// time, a value that is stable for a device-specific rotation period
// (p.Ext51764RotateDays days) and changes once that period elapses.
func Ext51764Value(deviceSeed []byte, p YandexAndroidParams, now time.Time) ([]byte, error) {
	groups, order, err := parseExt51764Template(p.Ext51764BaseVariant)
	if err != nil {
		return nil, err
	}

	periodDays := ext51764RotationPeriodDays(deviceSeed, p.Ext51764RotateDays)
	epoch := now.Unix() / 86400 / int64(periodDays)

	h := hmac.New(sha256.New, deviceSeed)
	h.Write([]byte("poisonproto-ext51764"))
	var epochBuf [8]byte
	binary.BigEndian.PutUint64(epochBuf[:], uint64(epoch))
	h.Write(epochBuf[:])
	seed := h.Sum(nil) // 32 bytes -> exact seed size for ChaCha8, deterministic per device+period

	var seed32 [32]byte
	copy(seed32[:], seed)
	rng := rand.New(rand.NewChaCha8(seed32))

	var recs []ext51764Record
	for _, prefix := range order {
		candidates := append([]byte{}, groups[prefix]...)
		if len(candidates) == 0 {
			continue
		}
		rng.Shuffle(len(candidates), func(i, j int) { candidates[i], candidates[j] = candidates[j], candidates[i] })
		n := 1 + rng.IntN(len(candidates)) // at least one number per group present
		chosen := candidates[:n]
		for _, num := range chosen {
			recs = append(recs, ext51764Record{prefix: []byte(prefix), number: num})
		}
	}
	rng.Shuffle(len(recs), func(i, j int) { recs[i], recs[j] = recs[j], recs[i] })

	return encodeExt51764(recs), nil
}

type ext51764Record struct {
	prefix []byte
	number byte
}

func encodeExt51764(recs []ext51764Record) []byte {
	body := make([]byte, 0, 64)
	for _, r := range recs {
		recLen := len(r.prefix) + 1
		body = append(body, byte(recLen))
		body = append(body, r.prefix...)
		body = append(body, r.number)
	}
	out := make([]byte, 2+len(body))
	binary.BigEndian.PutUint16(out[:2], uint16(len(body)))
	copy(out[2:], body)
	return out
}

var errBadExt51764Template = errors.New("fingerprint: malformed ext51764 base_variant")

// parseExt51764Template decodes the wire-format template (the same layout
// Ext51764Value produces: 2-byte length + records of [1B len][prefix][1B num])
// and learns, per distinct prefix, the set of numbers that template used —
// that set is the only universe we treat as "plausible" for that group, so a
// config change to base_variant changes what the generator can produce
// without any code change.
func parseExt51764Template(hexStr string) (groups map[string][]byte, order []string, err error) {
	raw, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, nil, errBadExt51764Template
	}
	if len(raw) < 2 {
		return nil, nil, errBadExt51764Template
	}
	totalLen := int(binary.BigEndian.Uint16(raw[:2]))
	body := raw[2:]
	if totalLen > len(body) {
		return nil, nil, errBadExt51764Template
	}
	body = body[:totalLen]

	groups = make(map[string][]byte)
	seen := make(map[string]map[byte]bool)
	i := 0
	for i < len(body) {
		recLen := int(body[i])
		i++
		if recLen < 1 || i+recLen > len(body) {
			return nil, nil, errBadExt51764Template
		}
		rec := body[i : i+recLen]
		i += recLen
		prefix := string(rec[:len(rec)-1])
		number := rec[len(rec)-1]
		if _, ok := seen[prefix]; !ok {
			seen[prefix] = make(map[byte]bool)
			order = append(order, prefix)
		}
		if !seen[prefix][number] {
			seen[prefix][number] = true
			groups[prefix] = append(groups[prefix], number)
		}
	}
	for _, nums := range groups {
		sort.Slice(nums, func(i, j int) bool { return nums[i] < nums[j] })
	}
	return groups, order, nil
}

// ext51764RotationPeriodDays derives a per-device rotation period within
// [min,max] days (ТЗ §5.7 point 3: devices must not all rotate in lockstep).
func ext51764RotationPeriodDays(deviceSeed []byte, rotateDays [2]int) int {
	lo, hi := rotateDays[0], rotateDays[1]
	if lo < 1 {
		lo = 1
	}
	if hi < lo {
		hi = lo
	}
	span := hi - lo + 1

	h := hmac.New(sha256.New, deviceSeed)
	h.Write([]byte("poisonproto-ext51764-period"))
	sum := h.Sum(nil)
	n := binary.BigEndian.Uint32(sum[:4]) % uint32(span)
	return lo + int(n)
}
