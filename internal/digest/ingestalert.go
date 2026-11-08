package digest

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"
)

// An ingest alert mails as soon as events stop reaching the hub, instead of
// waiting for the next daily digest. It mails when a problem starts or
// changes, reminds every alertRemind while it lasts, and mails once more when
// it clears.
const alertRemind = 6 * time.Hour

type alertState struct {
	Alerting  bool      `json:"alerting"`
	Signature string    `json:"signature"` // which spokes are in which bad state
	LastSent  time.Time `json:"last_sent"`
}

// Alert is one mail the ingest check wants sent; Commit records it as sent.
type Alert struct {
	Subject, Text, HTML string
	commit              func() error
}

// Commit saves the alert state; call it only after the mail went out, so a
// failed send is retried on the next run.
func (a *Alert) Commit() error { return a.commit() }

// IngestAlert checks /admin/health and returns the mail to send, or nil when
// nothing changed.
func IngestAlert(ctx context.Context, c *Client, persona, statePath string, now time.Time) (*Alert, error) {
	var st alertState
	if b, err := os.ReadFile(statePath); err == nil {
		_ = json.Unmarshal(b, &st)
	}
	var h IngestHealth
	if err := c.get(ctx, "/admin/health", nil, &h); err != nil {
		// A hub that cannot answer cannot ingest either.
		h = IngestHealth{Problems: []string{"hub admin API unreachable: " + err.Error()}}
		h.Spokes = append(h.Spokes, struct {
			SpokeID string `json:"spoke_id"`
			Status  string `json:"status"`
		}{"hub", "unreachable"})
	}
	var bad []string
	for _, s := range h.Spokes {
		if s.Status != "ok" {
			bad = append(bad, s.SpokeID+":"+s.Status)
		}
	}
	slices.Sort(bad)
	sig := strings.Join(bad, ",")
	broken := len(h.Problems) > 0
	save := func(next alertState) func() error {
		return func() error {
			b, _ := json.Marshal(next)
			tmp := statePath + ".tmp"
			if err := os.WriteFile(tmp, b, 0o600); err != nil {
				return err
			}
			return os.Rename(tmp, statePath)
		}
	}

	switch {
	case broken && (!st.Alerting || sig != st.Signature || now.Sub(st.LastSent) >= alertRemind):
		var b strings.Builder
		b.WriteString("Events are not reaching the hub, so the dashboard and digest undercount until this is fixed.\n\n")
		for _, p := range h.Problems {
			fmt.Fprintf(&b, "- %s\n", p)
		}
		b.WriteString("\nCheck: docker compose logs --since 30m hub spoke | grep -i 'ingest failed\\|shipping to hub failed\\|rejected'\n")
		verb := "Ingestion problem"
		if st.Alerting && sig == st.Signature {
			verb = "Still failing: ingestion problem"
		}
		return &Alert{
			Subject: fmt.Sprintf("[%s] ⚠ %s — %s", persona, verb, firstLine(h.Problems[0])),
			Text:    b.String(),
			HTML:    "<pre style=\"font:13px/1.5 ui-monospace,Menlo,monospace;white-space:pre-wrap\">" + esc(b.String()) + "</pre>",
			commit:  save(alertState{Alerting: true, Signature: sig, LastSent: now}),
		}, nil
	case !broken && st.Alerting:
		text := "Events are reaching the hub again. Anything queued on the spoke while it was failing is shipped in order.\n"
		return &Alert{
			Subject: fmt.Sprintf("[%s] ✓ Ingestion recovered", persona),
			Text:    text,
			HTML:    "<p style=\"font:14px/1.5 -apple-system,Segoe UI,sans-serif\">" + esc(text) + "</p>",
			commit:  save(alertState{LastSent: now}),
		}, nil
	}
	return nil, nil
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(s, " — ")
	return clip(s, 90)
}
