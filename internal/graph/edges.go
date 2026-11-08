// Package graph links sources (client addresses) through the things they
// share: planted keys, presented credentials, issued agent IDs, client
// stacks (TLS fingerprint plus user agent), prompts and registered agent
// names. The graph lives in PostgreSQL through the Apache AGE extension and
// is queried with openCypher.
package graph

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
	"unicode"

	"agenttrap/internal/events"
)

// Edge kinds, from a Source to an Entity.
const (
	ShownKey     = "shown_key"       // a planted key was revealed to the source
	UsedKey      = "used_key"        // the source used a planted key
	Credential   = "credential"      // the source presented a credential (not ours)
	IssuedAgent  = "issued_agent_id" // the source registered and got an agent ID
	SentAgent    = "sent_agent_id"   // the source sent an agent ID
	ClientStack  = "client_stack"    // TLS fingerprint and user agent pair
	Prompt       = "prompt"          // a chat prompt sent to the fake API
	AgentName    = "agent_name"      // the name it registered under
	OAuthClient  = "oauth_client"    // registered or used an OAuth client ID
	A2AContext   = "a2a_context"     // was issued or sent an A2A conversation context
	Webhook      = "webhook"         // asked for results to be pushed to a URL
	minPromptLen = 20                // shorter prompts ("hi") link unrelated clients
)

// Edge is one Source–Entity observation.
type Edge struct {
	Source string `json:"s"`
	Entity string `json:"e"` // kind-prefixed ID, e.g. "key:…"
	Kind   string `json:"k"`
	Label  string `json:"l"` // readable description of the entity
	Time   string `json:"t"` // RFC 3339, UTC
}

// EdgesFrom derives graph edges from events. Events without a linking
// entity yield nothing.
func EdgesFrom(evs []events.Event) []Edge {
	var out []Edge
	for _, ev := range evs {
		if ev.Source == "" {
			continue
		}
		add := func(entity, kind, label string) {
			out = append(out, Edge{Source: ev.Source, Entity: entity, Kind: kind, Label: clip(label, 160),
				Time: ev.Time.UTC().Format(time.RFC3339)})
		}
		str := func(k string) string { v, _ := ev.Detail[k].(string); return v }
		switch ev.Kind {
		case events.KindCanaryExposed:
			if id := str("exposure_id"); id != "" {
				add("key:"+id, ShownKey, "planted key "+ev.CanarySlot)
			}
		case events.KindCanaryUsed:
			switch {
			case str("exposure_id") != "":
				add("key:"+str("exposure_id"), UsedKey, "planted key "+ev.CanarySlot)
			case ev.CredentialSHA256 != "":
				add("cred:"+short(ev.CredentialSHA256), UsedKey, "planted key "+ev.CanarySlot)
			}
		case events.KindAuth:
			if ev.CredentialSHA256 != "" {
				add("cred:"+short(ev.CredentialSHA256), Credential, "credential "+str("prefix")+"…")
			}
		case events.KindToolCall:
			if id := str("agent_id"); id != "" {
				add("agent:"+id, IssuedAgent, "agent ID "+id)
			}
			if name := strings.TrimSpace(str("agent")); name != "" {
				add("name:"+hash(strings.ToLower(name)), AgentName, "registered as \""+name+"\"")
			}
			if p := normalize(str("last_message")); len(p) >= minPromptLen {
				add("prompt:"+hash(p), Prompt, "prompt \""+clip(str("last_message"), 80)+"\"")
			}
			if p := normalize(str("text")); ev.Protocol == "a2a" && len(p) >= minPromptLen {
				add("prompt:"+hash(p), Prompt, "prompt \""+clip(str("text"), 80)+"\"")
			}
			// Self-registered client IDs only: the service account's ID is
			// published to everyone who reaches the ops agent.
			if id := str("client_id"); strings.HasPrefix(id, "cli_") && len(id) == 20 && str("service_account") == "" {
				add("oauth:"+id, OAuthClient, "OAuth client "+id)
			}
			for _, k := range []string{"issued_context", "context_id"} {
				if id := str(k); id != "" {
					add("a2actx:"+hash(id), A2AContext, "A2A context "+clip(id, 40))
				}
			}
			if u := str("push_url"); u != "" {
				add("webhook:"+hash(strings.ToLower(u)), Webhook, "push webhook "+clip(u, 100))
			}
		case events.KindRequest:
			if id := str("agent_id"); id != "" {
				add("agent:"+id, SentAgent, "agent ID "+id)
			}
			if ja4 := str("ja4"); ja4 != "" && ev.UserAgent != "" {
				add("stack:"+hash(ja4+"|"+ev.UserAgent), ClientStack, "client stack "+ja4+" with "+clip(ev.UserAgent, 80))
			}
		}
	}
	return dedupe(out)
}

// dedupe keeps one edge per source, entity and kind: the latest.
func dedupe(in []Edge) []Edge {
	idx := map[[3]string]int{}
	var out []Edge
	for _, e := range in {
		k := [3]string{e.Source, e.Entity, e.Kind}
		if i, ok := idx[k]; ok {
			if e.Time > out[i].Time {
				out[i].Time = e.Time
			}
			continue
		}
		idx[k] = len(out)
		out = append(out, e)
	}
	return out
}

// normalize folds case and whitespace so trivially different copies of one
// prompt match.
func normalize(s string) string {
	return strings.Join(strings.FieldsFunc(strings.ToLower(s), unicode.IsSpace), " ")
}

func hash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:8])
}

func short(h string) string {
	if len(h) > 16 {
		return h[:16]
	}
	return h
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "") + "…"
}
