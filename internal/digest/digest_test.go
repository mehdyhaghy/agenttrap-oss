package digest

import (
	"strings"
	"testing"
	"time"
)

func TestFlag(t *testing.T) {
	for cc, want := range map[string]string{"DE": "🇩🇪", "us": "🇺🇸", "": "", "D": "", "D1": "", "EUR": ""} {
		if got := flag(cc); got != want {
			t.Errorf("flag(%q) = %q, want %q", cc, got, want)
		}
	}
}

func TestCountriesInDigest(t *testing.T) {
	r := &Report{
		CountryOf: map[string]string{"203.0.113.9": "NL"},
		Countries: []countryCount{{Code: "NL", Name: "Netherlands", Sources: 1}},
		Prompts:   map[string][]string{},
	}
	a := actor{Source: "203.0.113.9", Class: "rogue_agent", CountryCode: "NL", Country: "Netherlands"}
	r.Rogue = []actor{a}
	r.Sessions = []session{{Members: []string{"203.0.113.9", "198.51.100.1"}, Class: "rogue_agent"}}
	for name, body := range map[string]string{"text": r.Text(), "html": r.HTML()} {
		for _, want := range []string{"🇳🇱 203.0.113.9", "🇳🇱 Netherlands", "IP geolocation by DB-IP"} {
			if !strings.Contains(body, want) {
				t.Errorf("%s digest lacks %q", name, want)
			}
		}
		if strings.Contains(body, "🇳🇱 198.51.100.1") {
			t.Errorf("%s digest flagged an address with no known country", name)
		}
		if strings.Contains(body, "SSH tunnel") {
			t.Errorf("%s digest still carries the dashboard tunnel line", name)
		}
	}
}

func TestHeadlineMoods(t *testing.T) {
	now := time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)
	base := func() *Report {
		r := &Report{Since: now.Add(-24 * time.Hour), Until: now, CountryOf: map[string]string{}, Prompts: map[string][]string{},
			Classes: map[string]int{"scanner": 7, "crawler": 2}}
		r.Overview.Totals.Sources = 9
		return r
	}

	quiet := base()
	if got := quiet.Subject("DemoGPU"); got != "[DemoGPU] All quiet — no agents took the bait · 9 visitors — Sep 29" {
		t.Errorf("quiet subject: %s", got)
	}
	if got := quiet.Subline(); got != "9 visitors in the last 24 hours, mostly scanners." {
		t.Errorf("quiet subline: %s", got)
	}

	agents := base()
	agents.Agents = []actor{{Source: "198.51.100.4", Capability: 1, Depth: "engaged the agent surface", CountryCode: "JP", Country: "Japan"}}
	agents.CountryOf["198.51.100.4"] = "JP"
	if got := agents.Headline(); got != "No rogue agents — 1 AI agent came exploring" {
		t.Errorf("agents headline: %s", got)
	}
	if got := agents.Subline(); !strings.Contains(got, "🇯🇵 198.51.100.4, reached depth 1 of 7") || !strings.Contains(got, "came from 🇯🇵 Japan.") {
		t.Errorf("agents subline: %s", got)
	}

	rogue := base()
	rogue.Rogue = []actor{{Source: "203.0.113.9", Capability: 4, Depth: "used real credentials"}, {Source: "203.0.113.10", Capability: 2}}
	rogue.Overview.Severity = map[string]int{"critical": 1}
	if got := rogue.Subject("DemoGPU"); got != "[DemoGPU] 2 rogue agents took the bait · 1 critical (went deep, decoys only) — Sep 29" {
		t.Errorf("rogue subject: %s", got)
	}
	for name, page := range map[string]string{"quiet": quiet.HTML(), "agents": agents.HTML(), "rogue": rogue.HTML()} {
		if !strings.Contains(page, "</html>") || strings.Contains(page, "%!") {
			t.Errorf("%s HTML is malformed or has a formatting error", name)
		}
	}
}

func TestIncidentsExplained(t *testing.T) {
	now := time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC)
	r := &Report{Since: now.Add(-24 * time.Hour), Until: now, CountryOf: map[string]string{"203.0.113.9": "NL"}, Prompts: map[string][]string{}}
	r.Overview.Severity = map[string]int{"critical": 1, "medium": 1}
	r.Incidents = []incident{
		{Source: "198.51.100.7", Stages: []int{1, 2}, Score: 15, Severity: "medium", FirstSeen: now.Add(-3 * time.Hour), LastSeen: now.Add(-2 * time.Hour)},
		{Source: "203.0.113.9", Stages: []int{1, 2, 3, 4}, Score: 70, Severity: "critical", Relayed: true, FirstSeen: now.Add(-5 * time.Hour), LastSeen: now.Add(-time.Hour)},
	}
	sortIncidents(r.Incidents)
	if r.Incidents[0].Severity != "critical" {
		t.Fatalf("most severe incident not first: %+v", r.Incidents)
	}
	for name, body := range map[string]string{"text": r.Text(), "html": r.HTML()} {
		for _, want := range []string{
			"🇳🇱 203.0.113.9",
			"collected several",
			"shown a planted key → used a planted key → found a deep secret → used a deep secret",
			"a key shown to one address was used from another",
			"nothing to rotate or patch",
			"abuse contact",
			"Low: was shown a planted credential",
		} {
			if !strings.Contains(body, want) {
				t.Errorf("%s digest lacks %q", name, want)
			}
		}
		if strings.Contains(body, "%!") {
			t.Errorf("%s digest has a formatting error", name)
		}
	}
}

func TestExploitsSection(t *testing.T) {
	r := &Report{}
	r.Overview.Exploits = []exploitStat{{Module: "php2shell", Attack: "PHP2Shell", CVEs: []string{"CVE-2026-109618"}, Attempts: 3, Probes: 1, Sources: 2}}
	want := "PHP2Shell (CVE-2026-109618): 3 exploit attempts · 1 probe from 2 addresses"
	if !strings.Contains(r.Text(), want) || !strings.Contains(r.HTML(), "Exploit attempts on decoys") {
		t.Fatalf("exploit section missing:\n%s", r.Text())
	}
}
