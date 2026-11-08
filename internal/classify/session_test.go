package classify

import (
	"testing"
	"time"

	"agenttrap/internal/events"
)

func actorFrom(src, ua, ja4 string, at time.Time, extra ...events.Event) (Actor, []events.Event) {
	evs := []events.Event{{Time: at, Kind: events.KindRequest, Source: src, UserAgent: ua, Method: "GET", Path: "/", Status: 200,
		Surface: "www", Detail: map[string]any{"ja4": ja4}}}
	evs = append(evs, extra...)
	return Classify(src, evs), evs
}

// The real ChatGPT visit: one task spread across three addresses in a second.
func TestSessionChatGPTAcrossAddresses(t *testing.T) {
	ua := "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0"
	t0 := time.Date(2026, 9, 27, 7, 44, 18, 0, time.UTC)
	a1, e1 := actorFrom("9.129.8.32", ua, "t13d1713h2_5b57614c22b0_02c8e53ee398", t0)
	a2, e2 := actorFrom("9.129.8.43", ua, "t13d1713h2_5b57614c22b0_d5fe2c511efa", t0.Add(5*time.Second))
	a3, e3 := actorFrom("9.129.8.37", ua, "t13d1713h2_5b57614c22b0_ef7df7f74e48", t0.Add(5*time.Second))
	actors := []Actor{a1, a2, a3}
	sessions := GroupSessions(actors, map[string][]events.Event{a1.Source: e1, a2.Source: e2, a3.Source: e3})
	if len(sessions) != 1 || len(sessions[0].Members) != 3 {
		t.Fatalf("sessions: %+v", sessions)
	}
	for _, a := range actors {
		if a.SessionSize != 3 {
			t.Fatalf("member not tagged: %+v", a)
		}
	}
}

// Two strangers on the same Chrome build, different networks: not a session.
func TestSessionNoFalseMergeForCommonBrowsers(t *testing.T) {
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36"
	t0 := time.Now()
	a1, e1 := actorFrom("203.0.113.5", ua, "t13d1516h2_8daaf6152771_02713d6af862", t0)
	a2, e2 := actorFrom("198.51.100.9", ua, "t13d1516h2_8daaf6152771_02713d6af862", t0.Add(10*time.Second))
	if s := GroupSessions([]Actor{a1, a2}, map[string][]events.Event{a1.Source: e1, a2.Source: e2}); len(s) != 0 {
		t.Fatalf("unrelated browsers joined: %+v", s)
	}
}

// A key read at one address and used at another is one rogue agent even if
// neither address looks bad alone; the reader is upgraded.
func TestSessionRelayUpgradesReader(t *testing.T) {
	t0 := time.Now()
	reader, re := actorFrom("203.0.113.10", "python-httpx/0.28", "", t0,
		events.Event{Time: t0, Kind: events.KindCanaryExposed, Source: "203.0.113.10", CanarySlot: "docs_sample_key", Detail: map[string]any{"exposure_id": "ab"}})
	user, ue := actorFrom("198.51.100.20", "python-httpx/0.28", "", t0.Add(time.Hour),
		events.Event{Time: t0.Add(time.Hour), Kind: events.KindCanaryUsed, Source: "198.51.100.20", CanarySlot: "docs_sample_key",
			Detail: map[string]any{"exposed_to": "203.0.113.10"}})
	actors := []Actor{reader, user}
	sessions := GroupSessions(actors, map[string][]events.Event{reader.Source: re, user.Source: ue})
	if len(sessions) != 1 || sessions[0].Class != RogueAgent || actors[0].Class != RogueAgent {
		t.Fatalf("relay session: %+v / %+v", sessions, actors)
	}
}

// Scanners from one /24 at the same moment are one scanning run.
func TestSessionScannerRun(t *testing.T) {
	ua := "Mozilla/5.0 (l9scan/2.0; +https://leakix.net)"
	t0 := time.Now()
	a1, e1 := actorFrom("167.71.81.114", ua, "", t0)
	a2, e2 := actorFrom("138.68.82.23", ua, "", t0.Add(20*time.Second))
	s := GroupSessions([]Actor{a1, a2}, map[string][]events.Event{a1.Source: e1, a2.Source: e2})
	if len(s) != 1 {
		t.Fatalf("distinctive scanner run not joined: %+v", s)
	}
}

// A verified crawler must never be joined with an impersonator of it.
func TestSessionKeepsVerifiedCrawlerApart(t *testing.T) {
	ua := "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
	t0 := time.Now()
	real, e1 := actorFrom("66.249.66.1", ua, "", t0)
	fake, e2 := actorFrom("66.249.70.9", ua, "", t0.Add(5*time.Second))
	real.CrawlerCheck, fake.CrawlerCheck = "verified", "impersonation"
	if s := GroupSessions([]Actor{real, fake}, map[string][]events.Event{real.Source: e1, fake.Source: e2}); len(s) != 0 {
		t.Fatalf("verified crawler joined with impersonator: %+v", s)
	}
}

func TestSessionOfOperatorsIsOperator(t *testing.T) {
	t0 := time.Now()
	a, ea := actorFrom("198.51.100.7", "curl/8.7.1", "", t0,
		events.Event{Time: t0, Kind: events.KindCanaryExposed, Source: "198.51.100.7", CanarySlot: "docs_sample_key"})
	b, eb := actorFrom("203.0.113.10", "curl/8.18.0", "", t0.Add(time.Minute),
		events.Event{Time: t0.Add(time.Minute), Kind: events.KindCanaryUsed, Source: "203.0.113.10", CanarySlot: "docs_sample_key",
			Detail: map[string]any{"exposed_to": "198.51.100.7"}})
	MarkOperator(&a, "198.51.100.7/32")
	MarkOperator(&b, "203.0.113.10/32")
	s := GroupSessions([]Actor{a, b}, map[string][]events.Event{a.Source: ea, b.Source: eb})
	if len(s) != 1 || s[0].Class != Operator {
		t.Fatalf("operator session: %+v", s)
	}
}
