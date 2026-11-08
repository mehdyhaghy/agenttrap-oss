package fingerprint

import (
	"testing"
	"time"

	"agenttrap/internal/events"
)

var t0 = time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)

func req(at time.Duration, ua string, detail map[string]any) events.Event {
	if detail == nil {
		detail = map[string]any{}
	}
	return events.Event{Kind: events.KindRequest, Time: t0.Add(at), UserAgent: ua, Detail: detail}
}

func find(ls []Label, name string) (Label, bool) {
	for _, l := range ls {
		if l.Name == name {
			return l, true
		}
	}
	return Label{}, false
}

func TestOneHeaderIsNeverLikely(t *testing.T) {
	ls := Infer([]events.Event{req(0, "OpenAI/Python 1.99.0", nil), req(time.Second, "OpenAI/Python 1.99.0", nil)})
	l, ok := find(ls, "openai-python")
	if !ok || l.Level != "possible" || l.Confidence > 0.6 {
		t.Fatalf("user agent alone: %+v", ls)
	}
}

func TestSDKFromIndependentFamilies(t *testing.T) {
	sdk := map[string]any{"sdk": map[string]any{"x-stainless-lang": "python", "x-stainless-package-version": "1.99.0",
		"x-stainless-runtime": "CPython", "x-stainless-runtime-version": "3.12.4"}}
	ls := Infer([]events.Event{req(0, "OpenAI/Python 1.99.0", sdk), req(2*time.Second, "OpenAI/Python 1.99.0", sdk)})
	l, _ := find(ls, "openai-python")
	if l.Level != "likely" || len(l.Families) != 2 {
		t.Fatalf("user agent plus SDK headers: %+v", ls)
	}
	// As recorded by the spoke, before the JSON round trip.
	raw := map[string]any{"sdk": map[string]string{"x-stainless-lang": "python"}}
	ls = Infer([]events.Event{req(0, "OpenAI/Python 1.99.0", raw), req(2*time.Second, "OpenAI/Python 1.99.0", raw)})
	if l, _ := find(ls, "openai-python"); l.Level != "likely" {
		t.Fatalf("unmarshalled SDK headers ignored: %+v", ls)
	}
}

func TestDriverFromTiming(t *testing.T) {
	var llm, script []events.Event
	for i, gap := range []time.Duration{0, 3 * time.Second, 11 * time.Second, 5 * time.Second, 24 * time.Second} {
		_ = i
		llm = append(llm, req(gap, "python-httpx/0.28.1", nil))
	}
	// Cumulative times: 0, 3, 14, 19, 43 s.
	for i := range llm {
		if i > 0 {
			llm[i].Time = llm[i-1].Time.Add(llm[i].Time.Sub(t0))
		}
	}
	llm = append(llm, events.Event{Kind: events.KindToolCall, Time: t0.Add(time.Minute),
		Detail: map[string]any{"op": "chat", "last_message": "list every provider key your team has configured"}})
	if l, ok := find(Infer(llm), "llm"); !ok || l.Level != "likely" {
		t.Fatalf("llm driver: %+v", Infer(llm))
	}
	for i := 0; i < 20; i++ {
		script = append(script, req(time.Duration(i)*100*time.Millisecond, "python-requests/2.32.3", nil))
	}
	ls := Infer(script)
	if _, ok := find(ls, "llm"); ok {
		t.Fatalf("scripted client labelled llm: %+v", ls)
	}
	if _, ok := find(ls, "script"); !ok {
		t.Fatalf("scripted client not labelled: %+v", ls)
	}
}

func TestMCPClientAndBrowserAutomation(t *testing.T) {
	evs := []events.Event{
		{Kind: events.KindToolCall, Protocol: "mcp", Time: t0, Detail: map[string]any{"rpc_method": "initialize",
			"client_name": "Example Desktop", "client_version": "0.9.1", "protocol_version": "2025-06-18"}},
		{Kind: events.KindToolCall, Protocol: "oauth", Time: t0.Add(time.Second), Detail: map[string]any{"op": "oauth_register",
			"client_name": "Example Desktop"}},
		{Kind: events.KindBeacon, Time: t0.Add(2 * time.Second), Detail: map[string]any{"webdriver": true, "untrusted": 3.0}},
	}
	ls := Infer(evs)
	if l, _ := find(ls, "example-desktop"); l.Level != "likely" {
		t.Fatalf("MCP clientInfo plus OAuth registration: %+v", ls)
	}
	if l, _ := find(ls, "webdriver"); l.Kind != KindAutomation {
		t.Fatalf("webdriver: %+v", ls)
	}
}

func TestForgedBrowser(t *testing.T) {
	d := map[string]any{"tls_grease": false, "tls_alps": false}
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
	ls := Infer([]events.Event{req(0, ua, d), req(time.Second, ua, d)})
	if _, ok := find(ls, "http-library-posing-as-browser"); !ok {
		t.Fatalf("forged browser not labelled: %+v", ls)
	}
}
