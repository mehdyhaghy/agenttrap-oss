// Package events defines the normalized interaction event shared by spokes and the hub.
package events

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

// Kinds of events emitted by adapters.
const (
	KindRequest       = "request"        // any inbound request
	KindAuth          = "auth"           // credential presented (valid or not)
	KindCanaryExposed = "canary_exposed" // a canary value was shown to the client
	KindCanaryUsed    = "canary_used"    // a canary value was presented back to us
	KindToolCall      = "tool_call"      // MCP tool invocation
	KindForm          = "form"           // form submission (waitlist, login)
	KindTLSHello      = "tls_hello"      // TLS ClientHello fingerprint from the packet sensor
	KindBeacon        = "beacon"         // page script report: JS ran, automation flags, input behavior
	KindReplay        = "replay"         // rrweb recording chunk (stored apart from events by the hub)
	KindConnect       = "connect"        // a non-HTTP connection (SSH) and its client banner
	KindThrottled     = "throttled"      // rollup standing in for bulk traffic dropped by the per-source event limit
	KindExploit       = "exploit"        // a request a module recognized as an attack on a known vulnerability
)

// Event is one observed interaction. SpokeID is always set by the hub from the
// spoke's certificate identity; any value sent by a spoke is ignored.
type Event struct {
	ID               string         `json:"id"`
	SpokeID          string         `json:"spoke_id,omitempty"`
	Time             time.Time      `json:"time"`
	Protocol         string         `json:"protocol"` // http, openai, mcp, a2a, oauth, ssh
	Surface          string         `json:"surface"`  // www, docs, api, console, mcp, status, vllm
	Kind             string         `json:"kind"`
	Source           string         `json:"source"` // client address, possibly pseudonymized
	UserAgent        string         `json:"user_agent,omitempty"`
	Method           string         `json:"method,omitempty"`
	Host             string         `json:"host,omitempty"`
	Path             string         `json:"path,omitempty"`
	Status           int            `json:"status,omitempty"`
	CanarySlot       string         `json:"canary_slot,omitempty"`
	CredentialSHA256 string         `json:"credential_sha256,omitempty"`
	Detail           map[string]any `json:"detail,omitempty"`
}

// FromModule reports whether a canary event concerns a key a honeypot module
// handed out (a planted .env, a leaked config): exposed by a module, or used
// after one exposed it. Such keys are harvested in bulk by scanners, so they
// are counted apart from the persona's canary chain.
func (e Event) FromModule() bool {
	if e.Kind != KindCanaryExposed && e.Kind != KindCanaryUsed {
		return false
	}
	m, _ := e.Detail["module"].(string)
	by, _ := e.Detail["exposed_by"].(string)
	return m != "" || by != ""
}

// Batch is the unit shipped from a spoke to the hub.
type Batch struct {
	ID     string  `json:"id"`
	Events []Event `json:"events"`
	// Shipping health, filled in at send time: batches still waiting on the
	// spoke (this one included) and batches it set aside after a refusal.
	QueueDepth  int `json:"queue_depth,omitempty"`
	HeldOnSpoke int `json:"held_on_spoke,omitempty"`
}

// NewID returns a random 128-bit hex identifier.
func NewID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}
