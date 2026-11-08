package worldpack

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"agenttrap/personas"
)

func TestSignOpenAndTamper(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	env := Sign(priv, personas.DemoGPU)
	p, err := Open(pub, env)
	if err != nil {
		t.Fatal(err)
	}
	if p.Company.Domain != "demogpu.example" {
		t.Fatalf("domain %q", p.Company.Domain)
	}
	env.Payload = append([]byte{}, env.Payload...)
	env.Payload[10] ^= 1
	if _, err := Open(pub, env); err == nil {
		t.Fatal("tampered pack accepted")
	}
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := Open(otherPub, Sign(priv, personas.DemoGPU)); err == nil {
		t.Fatal("pack accepted under wrong key")
	}
}

func TestParseRejectsUnknownSlot(t *testing.T) {
	_, err := Parse([]byte(`{"id":"x","version":"1","company":{"domain":"x.com"},
		"canaries":[{"slot":"a","prefix":"p","length":16}],
		"chain":[{"stage":1,"kind":"canary_used","slot":"missing","score":1}]}`))
	if err == nil {
		t.Fatal("expected error")
	}
}
