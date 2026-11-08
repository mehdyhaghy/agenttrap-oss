// Package canary derives per-spoke canary values from a hub-issued seed.
//
// The hub keeps each spoke's seed, so it can recompute every canary a spoke
// serves and recognise one presented anywhere, including at another spoke.
package canary

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"regexp"
	"slices"
	"strings"

	"agenttrap/internal/worldpack"
)

const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// Derive returns the canary value for spec under seed.
func Derive(seed []byte, spec worldpack.CanarySpec) string {
	out := make([]byte, 0, len(spec.Prefix)+spec.Length)
	out = append(out, spec.Prefix...)
	for counter := uint32(0); len(out) < len(spec.Prefix)+spec.Length; counter++ {
		mac := hmac.New(sha256.New, seed)
		var c [4]byte
		binary.BigEndian.PutUint32(c[:], counter)
		mac.Write([]byte(spec.Slot))
		mac.Write(c[:])
		for _, b := range mac.Sum(nil) {
			// 62*4 = 248; rejecting bytes >= 248 keeps the distribution uniform.
			if b >= 248 {
				continue
			}
			out = append(out, alphabet[b%62])
			if len(out) == len(spec.Prefix)+spec.Length {
				break
			}
		}
	}
	return string(out)
}

// Hash is the identifier used to match a presented credential against canaries
// without shipping the raw value.
func Hash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// Set holds one spoke's canaries: a fixed value per slot (kept so values
// published earlier stay live) and the ability to mint per-exposure values.
type Set struct {
	seed   []byte
	specs  map[string]worldpack.CanarySpec
	bySlot map[string]string
	mintRE map[string]*regexp.Regexp // per-slot matcher for minted values in text
}

// NewSet derives every canary in pack for seed.
func NewSet(seed []byte, pack *worldpack.Pack) *Set {
	s := &Set{seed: slices.Clone(seed), specs: map[string]worldpack.CanarySpec{},
		bySlot: make(map[string]string, len(pack.Canaries)), mintRE: map[string]*regexp.Regexp{}}
	for _, spec := range pack.Canaries {
		s.specs[spec.Slot] = spec
		s.bySlot[spec.Slot] = Derive(seed, spec)
		s.mintRE[spec.Slot] = regexp.MustCompile(regexp.QuoteMeta(spec.Prefix) + fmt.Sprintf("[0-9A-Za-z]{%d}", spec.Length))
	}
	return s
}

// Mint returns a new per-exposure value for slot and its exposure ID.
func (s *Set) Mint(slot string) (value, exposureID string) {
	spec, ok := s.specs[slot]
	if !ok {
		return "", ""
	}
	return Mint(s.seed, spec)
}

// Reveal returns a value to show for slot and its exposure ID. It mints a
// per-exposure value when the slot is long enough to carry one; a fixed-shape
// credential too short to hold the minted payload (an AWS access key id is only
// 20 characters) gets the spoke's fixed value instead, matched by equality, so
// the exposure ID is empty. Either is recognised by Identify.
func (s *Set) Reveal(slot string) (value, exposureID string) {
	spec, ok := s.specs[slot]
	if !ok {
		return "", ""
	}
	if spec.Length >= mintDigits {
		return Mint(s.seed, spec)
	}
	return s.bySlot[slot], ""
}

// Identify reports which slot presented belongs to and, for minted values,
// the exposure ID it was issued with.
func (s *Set) Identify(presented string) (slot, exposureID string, ok bool) {
	if slot, ok := s.Match(presented); ok {
		return slot, "", true
	}
	for slot, spec := range s.specs {
		if id, ok := VerifyMinted(s.seed, spec, presented); ok {
			return slot, id, true
		}
	}
	return "", "", false
}

// Found is a canary located inside a larger payload.
type Found struct {
	Slot       string
	ExposureID string // empty for a fixed spoke value
}

// Scan finds every canary embedded in text: fixed spoke values by substring,
// and minted per-exposure values by shape and MAC. The egress broker uses it to
// detect a canary leaving through an outbound channel (exfiltration).
func (s *Set) Scan(text string) []Found {
	if text == "" {
		return nil
	}
	var out []Found
	seen := map[string]bool{}
	add := func(slot, id string) {
		k := slot + "|" + id
		if !seen[k] {
			seen[k] = true
			out = append(out, Found{Slot: slot, ExposureID: id})
		}
	}
	for slot, val := range s.bySlot {
		if strings.Contains(text, val) {
			add(slot, "")
		}
	}
	for slot, spec := range s.specs {
		re := s.mintRE[slot]
		if re == nil {
			continue
		}
		for _, m := range re.FindAllString(text, -1) {
			if id, ok := VerifyMinted(s.seed, spec, m); ok {
				add(slot, id)
			}
		}
	}
	return out
}

// LooksLike reports whether presented has the shape of one of this pack's
// canaries (prefix and length), so it may be another spoke's minted value.
func (s *Set) LooksLike(presented string) bool {
	for _, spec := range s.specs {
		if body, ok := strings.CutPrefix(presented, spec.Prefix); ok && len(body) == spec.Length {
			return true
		}
	}
	return false
}

// Subkey derives 32 bytes of key material for label from the seed, for
// per-spoke values that must stay stable but are not canaries themselves.
func (s *Set) Subkey(label string) []byte {
	mac := hmac.New(sha256.New, s.seed)
	mac.Write([]byte("subkey:" + label))
	return mac.Sum(nil)
}

// Value returns the canary for slot.
func (s *Set) Value(slot string) string { return s.bySlot[slot] }

// Match returns the slot whose canary equals presented, if any.
func (s *Set) Match(presented string) (string, bool) {
	if presented == "" {
		return "", false
	}
	for slot, v := range s.bySlot {
		if subtle.ConstantTimeCompare([]byte(v), []byte(presented)) == 1 {
			return slot, true
		}
	}
	return "", false
}

// Slots returns slot -> value, for the hub's canary index.
func (s *Set) Slots() map[string]string { return s.bySlot }

// Minted canaries are unique per exposure: every page view or reveal gets
// its own value, so a later use can be traced to the exact exposure even
// from another IP address. A minted value carries a random exposure ID and a
// MAC under the spoke seed, so it can be verified without being stored.
//
// Layout (base62): 9-byte exposure ID || 14-byte MAC in the last 31
// characters. Any characters before them are filler derived from the
// payload, so a long value does not start with a run of zeros. Values minted
// before the filler existed have zeros there and still verify.
const (
	mintIDLen  = 9
	mintMACLen = 14
	mintDigits = 31 // base62 digits needed for 23 bytes
)

func mintMAC(seed []byte, slot string, id []byte) []byte {
	mac := hmac.New(sha256.New, seed)
	mac.Write([]byte("mint:" + slot + ":"))
	mac.Write(id)
	return mac.Sum(nil)[:mintMACLen]
}

// Mint returns a new unique value for spec and its exposure ID (hex).
func Mint(seed []byte, spec worldpack.CanarySpec) (value, exposureID string) {
	id := make([]byte, mintIDLen)
	if _, err := rand.Read(id); err != nil {
		panic(err)
	}
	payload := append(slices.Clone(id), mintMAC(seed, spec.Slot, id)...)
	return spec.Prefix + filler(payload, spec.Length-mintDigits) + encode62(payload, mintDigits), hex.EncodeToString(id)
}

// filler returns n base62 characters derived from payload.
func filler(payload []byte, n int) string {
	out := make([]byte, 0, max(n, 0))
	for counter := byte(0); len(out) < n; counter++ {
		sum := sha256.Sum256(append([]byte{counter}, payload...))
		for _, b := range sum {
			if b < 248 && len(out) < n {
				out = append(out, alphabet[b%62])
			}
		}
	}
	return string(out)
}

// VerifyMinted checks value against spec under seed and returns the exposure ID.
func VerifyMinted(seed []byte, spec worldpack.CanarySpec, value string) (string, bool) {
	body, ok := strings.CutPrefix(value, spec.Prefix)
	if !ok || len(body) != spec.Length || len(body) < mintDigits {
		return "", false
	}
	payload, ok := decode62(body[len(body)-mintDigits:], mintIDLen+mintMACLen)
	if !ok {
		return "", false
	}
	id, got := payload[:mintIDLen], payload[mintIDLen:]
	if subtle.ConstantTimeCompare(got, mintMAC(seed, spec.Slot, id)) != 1 {
		return "", false
	}
	pad := body[:len(body)-mintDigits]
	if pad != filler(payload, len(pad)) && strings.Trim(pad, "0") != "" {
		return "", false
	}
	return hex.EncodeToString(id), true
}

// encode62 writes b as a fixed-width base62 number.
func encode62(b []byte, width int) string {
	n := new(big.Int).SetBytes(b)
	base := big.NewInt(62)
	out := make([]byte, width)
	for i := width - 1; i >= 0; i-- {
		var m big.Int
		n.DivMod(n, base, &m)
		out[i] = alphabet[m.Int64()]
	}
	return string(out)
}

// decode62 parses a base62 string into exactly size bytes.
func decode62(s string, size int) ([]byte, bool) {
	n := new(big.Int)
	base := big.NewInt(62)
	for i := 0; i < len(s); i++ {
		d := strings.IndexByte(alphabet, s[i])
		if d < 0 {
			return nil, false
		}
		n.Mul(n, base)
		n.Add(n, big.NewInt(int64(d)))
	}
	if n.BitLen() > size*8 {
		return nil, false
	}
	out := make([]byte, size)
	return n.FillBytes(out), true
}
