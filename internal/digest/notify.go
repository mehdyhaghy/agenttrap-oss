package digest

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"net/mail"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

// Submission is one contact form message.
type Submission struct {
	ID      string
	Time    time.Time
	Source  string
	Name    string
	ReplyTo string
	Topic   string
	Message string
}

type formEvent struct {
	ID     string         `json:"id"`
	Time   time.Time      `json:"time"`
	Source string         `json:"source"`
	Detail map[string]any `json:"detail"`
}

// notifyState remembers what was already forwarded.
type notifyState struct {
	Sent map[string]time.Time `json:"sent"` // event ID -> when forwarded
}

// NewSubmissions returns contact form messages not yet forwarded according to
// the state file, oldest first.
func NewSubmissions(ctx context.Context, c *Client, statePath string) ([]Submission, *notifyState, error) {
	st := &notifyState{Sent: map[string]time.Time{}}
	if b, err := os.ReadFile(statePath); err == nil {
		_ = json.Unmarshal(b, st)
	}
	var evs []formEvent
	if err := c.get(ctx, "/admin/events", url.Values{"kind": {"form"}, "hours": {"48"}, "limit": {"1000"}}, &evs); err != nil {
		return nil, nil, err
	}
	var out []Submission
	for _, e := range evs {
		if e.Detail["form"] != "contact" {
			continue
		}
		if _, done := st.Sent[e.ID]; done {
			continue
		}
		str := func(k string) string { v, _ := e.Detail[k].(string); return v }
		out = append(out, Submission{ID: e.ID, Time: e.Time, Source: e.Source, Name: str("name"),
			ReplyTo: str("reply_to"), Topic: str("topic"), Message: str("message")})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Time.Before(out[j].Time) })
	return out, st, nil
}

// MarkSent records forwarded submissions and prunes entries older than a week.
func (st *notifyState) MarkSent(ids []string, statePath string) error {
	now := time.Now().UTC()
	for _, id := range ids {
		st.Sent[id] = now
	}
	for id, t := range st.Sent {
		if now.Sub(t) > 7*24*time.Hour {
			delete(st.Sent, id)
		}
	}
	b, _ := json.Marshal(st)
	tmp := statePath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, statePath)
}

// ValidReplyTo returns addr if it is a single well-formed address.
func ValidReplyTo(addr string) string {
	a, err := mail.ParseAddress(strings.TrimSpace(addr))
	if err != nil || strings.ContainsAny(a.Address, "\r\n") {
		return ""
	}
	return a.Address
}

// SubmissionMail renders one submission as subject, text and HTML.
func SubmissionMail(persona string, s Submission) (string, string, string) {
	subject := fmt.Sprintf("[%s contact] %s from %s", persona, orDash(s.Topic), orDash(s.Name))
	text := fmt.Sprintf("Topic: %s\nName: %s\nReply to: %s\nSource IP: %s\nReceived: %s UTC\n\n%s\n",
		orDash(s.Topic), orDash(s.Name), orDash(s.ReplyTo), s.Source, s.Time.UTC().Format("2006-01-02 15:04"), s.Message)
	body := fmt.Sprintf(`<table style="font:14px/1.5 -apple-system,Segoe UI,sans-serif;border-collapse:collapse">
<tr><td style="color:#666;padding:2px 12px 2px 0">Topic</td><td>%s</td></tr>
<tr><td style="color:#666;padding:2px 12px 2px 0">Name</td><td>%s</td></tr>
<tr><td style="color:#666;padding:2px 12px 2px 0">Reply to</td><td>%s</td></tr>
<tr><td style="color:#666;padding:2px 12px 2px 0">Source IP</td><td><code>%s</code></td></tr>
<tr><td style="color:#666;padding:2px 12px 2px 0">Received</td><td>%s UTC</td></tr>
</table><div style="margin-top:14px;padding:12px;border-left:3px solid #2a78d6;background:#f4f6fa;white-space:pre-wrap;font:14px/1.5 -apple-system,Segoe UI,sans-serif">%s</div>`,
		html.EscapeString(orDash(s.Topic)), html.EscapeString(orDash(s.Name)), html.EscapeString(orDash(s.ReplyTo)),
		html.EscapeString(s.Source), s.Time.UTC().Format("2006-01-02 15:04"), html.EscapeString(s.Message))
	return subject, text, body
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}
