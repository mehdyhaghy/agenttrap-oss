package hub

import (
	"bytes"
	"encoding/json"
	"strings"

	"agenttrap/internal/events"
)

// Postgres refuses NUL in text and \u0000 in jsonb (SQLSTATE 22P05), and
// rejects invalid UTF-8 in either. Attackers send all three, so every string
// an event carries is cleaned before it reaches the store. NUL becomes the
// visible U+2400 symbol so the evidence that one was sent survives.
const nulSymbol = "␀"

func cleanText(s string) string {
	s = strings.ToValidUTF8(s, "�")
	return strings.ReplaceAll(s, "\x00", nulSymbol)
}

func cleanValue(v any) any {
	switch t := v.(type) {
	case string:
		return cleanText(t)
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[cleanText(k)] = cleanValue(x)
		}
		return out
	case []any:
		for i, x := range t {
			t[i] = cleanValue(x)
		}
		return t
	}
	return v
}

// sanitizeEvent makes every string field of ev storable.
func sanitizeEvent(ev *events.Event) {
	for _, p := range []*string{&ev.ID, &ev.Protocol, &ev.Surface, &ev.Kind, &ev.Source, &ev.UserAgent,
		&ev.Method, &ev.Host, &ev.Path, &ev.CanarySlot, &ev.CredentialSHA256} {
		*p = cleanText(*p)
	}
	if ev.Detail != nil {
		ev.Detail = cleanValue(ev.Detail).(map[string]any)
	}
}

// cleanJSON returns raw JSON that jsonb will accept, re-encoding it only when
// it holds an escaped NUL.
func cleanJSON(raw []byte) []byte {
	if !bytes.Contains(raw, []byte(`\u0000`)) {
		return raw
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return raw
	}
	out, err := json.Marshal(cleanValue(v))
	if err != nil {
		return raw
	}
	return out
}
