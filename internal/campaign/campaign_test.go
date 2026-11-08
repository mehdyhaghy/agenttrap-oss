package campaign

import (
	"slices"
	"strings"
	"testing"
	"time"

	"agenttrap/internal/classify"
	"agenttrap/internal/fingerprint"
)

var t0 = time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)

func agent(src string, stage int, at time.Duration) classify.Actor {
	a := classify.Actor{Source: src, Class: classify.RogueAgent, Score: 60, FirstSeen: t0.Add(at), LastSeen: t0.Add(at + time.Minute)}
	a.Features.MaxStage = stage
	return a
}

func TestJoinsOnHardLinksAndIdentity(t *testing.T) {
	a := agent("203.0.113.1", 3, 0)
	b := agent("198.51.100.2", 4, 2*time.Hour)
	b.Links = []classify.Link{{Agent: a.Source, Class: classify.RogueAgent, Via: []string{"planted key provider_key_vllm"}}}
	c := agent("192.0.2.3", 1, 30*time.Hour)
	c.Features.AgentName = "KeyHelper"
	d := agent("192.0.2.4", 2, 31*time.Hour)
	d.Features.AgentName = "keyhelper"
	lone := agent("192.0.2.99", 2, 0)
	crawler := classify.Actor{Source: "192.0.2.50", Class: classify.Crawler}
	cs := Correlate([]classify.Actor{a, b, c, d, lone, crawler})
	if len(cs) != 2 {
		t.Fatalf("want two campaigns: %+v", cs)
	}
	top := cs[0]
	if !slices.Equal(top.Members, []string{"198.51.100.2", "203.0.113.1"}) || top.Severity != "critical" ||
		!strings.Contains(strings.Join(top.Joins, ";"), "linked through planted key") {
		t.Fatalf("linked campaign: %+v", top)
	}
	if cs[1].Severity != "medium" || !strings.Contains(cs[1].Joins[0], "registered as keyhelper") {
		t.Fatalf("identity campaign: %+v", cs[1])
	}
	// Named after the earliest member, so the ID survives new members.
	again := Correlate([]classify.Actor{a, b})
	if again[0].ID != top.ID {
		t.Fatal("campaign ID changed")
	}
}

// Platform fleets are not campaigns: a declared crawler, a platform's user
// agent with no behavior, and a shared operator URL join nothing.
func TestPlatformFleetsAreNotCampaigns(t *testing.T) {
	var fleet []classify.Actor
	for i, src := range []string{"66.249.64.8", "66.249.64.9", "9.129.8.32", "9.129.8.43"} {
		a := classify.Actor{Source: src, Class: classify.AIAgent, Score: 10, FirstSeen: t0, LastSeen: t0.Add(time.Minute),
			Identity: &classify.Identity{Name: "PlatformBot", URL: "https://platform.example/bot"}, SessionID: "s-1"}
		if i < 2 {
			a.Class, a.Score, a.CrawlerCheck = classify.Crawler, 30, "verified"
			a.Features.DeclaredAs = "crawler"
		}
		fleet = append(fleet, a)
	}
	if cs := Correlate(fleet); len(cs) != 0 {
		t.Fatalf("platform fleet became a campaign: %+v", cs)
	}
}

func TestBehaviorAloneDoesNotJoin(t *testing.T) {
	x := agent("203.0.113.7", 2, 0)
	y := agent("203.0.113.8", 2, time.Hour)
	x.ClusterID, y.ClusterID = "c-1", "c-1"
	if cs := Correlate([]classify.Actor{x, y}); len(cs) != 0 {
		t.Fatalf("same behavior alone made a campaign: %+v", cs)
	}
	sdk := fingerprint.Label{Name: "openai-python", Level: "likely"}
	x.Frameworks, y.Frameworks = []fingerprint.Label{sdk}, []fingerprint.Label{sdk}
	cs := Correlate([]classify.Actor{x, y})
	if len(cs) != 1 || !strings.Contains(cs[0].Joins[0], "openai-python") {
		t.Fatalf("behavior plus software: %+v", cs)
	}
}
