package canary

import (
	"strings"
	"testing"

	"agenttrap/internal/worldpack"
)

func TestDeriveDeterministicAndPerSeed(t *testing.T) {
	spec := worldpack.CanarySpec{Slot: "k", Prefix: "dgp_test_", Length: 32}
	a1 := Derive([]byte("seed-a"), spec)
	a2 := Derive([]byte("seed-a"), spec)
	b := Derive([]byte("seed-b"), spec)
	if a1 != a2 {
		t.Fatal("not deterministic")
	}
	if a1 == b {
		t.Fatal("different seeds produced the same canary")
	}
	if !strings.HasPrefix(a1, "dgp_test_") || len(a1) != len("dgp_test_")+32 {
		t.Fatalf("bad shape: %q", a1)
	}
	other := Derive([]byte("seed-a"), worldpack.CanarySpec{Slot: "k2", Prefix: "dgp_test_", Length: 32})
	if other == a1 {
		t.Fatal("different slots produced the same canary")
	}
}

func TestSetMatch(t *testing.T) {
	p := &worldpack.Pack{Canaries: []worldpack.CanarySpec{{Slot: "a", Prefix: "x_", Length: 20}}}
	s := NewSet([]byte("seed"), p)
	if slot, ok := s.Match(s.Value("a")); !ok || slot != "a" {
		t.Fatal("expected match")
	}
	if _, ok := s.Match("x_nope"); ok {
		t.Fatal("unexpected match")
	}
	if _, ok := s.Match(""); ok {
		t.Fatal("empty must not match")
	}
}

func TestMintVerify(t *testing.T) {
	spec := worldpack.CanarySpec{Slot: "docs_sample_key", Prefix: "dgp_test_", Length: 32}
	seed := []byte("spoke-seed")
	v1, id1 := Mint(seed, spec)
	v2, id2 := Mint(seed, spec)
	if v1 == v2 || id1 == id2 || len(v1) != len("dgp_test_")+32 {
		t.Fatalf("mint not unique or wrong length: %s %s", v1, v2)
	}
	if got, ok := VerifyMinted(seed, spec, v1); !ok || got != id1 {
		t.Fatalf("verify: %v %s", ok, got)
	}
	if _, ok := VerifyMinted([]byte("other-seed"), spec, v1); ok {
		t.Fatal("verified under the wrong seed")
	}
	other := worldpack.CanarySpec{Slot: "provider_key_vllm", Prefix: "dgp_test_", Length: 32}
	if _, ok := VerifyMinted(seed, other, v1); ok {
		t.Fatal("verified for the wrong slot")
	}
	// A single changed character fails.
	b := []byte(v1)
	if b[20] == 'a' {
		b[20] = 'b'
	} else {
		b[20] = 'a'
	}
	if _, ok := VerifyMinted(seed, spec, string(b)); ok {
		t.Fatal("tampered value verified")
	}
	// Fixed values still verify through the set, and minted ones carry an ID.
	p := &worldpack.Pack{Canaries: []worldpack.CanarySpec{spec}}
	set := NewSet(seed, p)
	if slot, id, ok := set.Identify(set.Value("docs_sample_key")); !ok || slot != "docs_sample_key" || id != "" {
		t.Fatal("fixed value not identified")
	}
	v, wantID := set.Mint("docs_sample_key")
	if slot, id, ok := set.Identify(v); !ok || slot != "docs_sample_key" || id != wantID {
		t.Fatalf("minted value not identified: %v %s", ok, id)
	}
	if !set.LooksLike(v) || set.LooksLike("dgp_test_short") {
		t.Fatal("LooksLike")
	}
}

func TestMintFillerAndLegacyZeros(t *testing.T) {
	seed := []byte("seed")
	spec := worldpack.CanarySpec{Slot: "tok", Prefix: "gla_", Length: 40}
	v, id := Mint(seed, spec)
	body := strings.TrimPrefix(v, spec.Prefix)
	if strings.HasPrefix(body, "000") {
		t.Fatalf("minted value starts with a zero run: %s", v)
	}
	if got, ok := VerifyMinted(seed, spec, v); !ok || got != id {
		t.Fatal("filled value does not verify")
	}
	// Values minted before the filler (zeros in front) still verify.
	legacy := spec.Prefix + strings.Repeat("0", spec.Length-mintDigits) + body[spec.Length-mintDigits:]
	if _, ok := VerifyMinted(seed, spec, legacy); !ok {
		t.Fatal("legacy zero-padded value rejected")
	}
	// Any other filler is a forgery.
	forged := spec.Prefix + strings.Repeat("A", spec.Length-mintDigits) + body[spec.Length-mintDigits:]
	if _, ok := VerifyMinted(seed, spec, forged); ok {
		t.Fatal("forged filler accepted")
	}
}
