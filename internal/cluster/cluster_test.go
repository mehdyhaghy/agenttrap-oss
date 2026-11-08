package cluster

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"agenttrap/internal/classify"
	"agenttrap/internal/events"
)

var t0 = time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)

// agentRun is one address walking the MCP chain the way one agent build does.
func agentRun(src string, start time.Duration) []events.Event {
	at := t0.Add(start)
	step := func(d time.Duration, ev events.Event) events.Event {
		at = at.Add(d)
		ev.Time, ev.Source = at, src
		if ev.Detail == nil {
			ev.Detail = map[string]any{}
		}
		return ev
	}
	ua := "OpenAI/Python 1.99.0"
	return []events.Event{
		step(0, events.Event{Kind: events.KindRequest, Surface: "www", Method: "GET", Path: "/llms.txt", UserAgent: ua, Status: 200}),
		step(4*time.Second, events.Event{Kind: events.KindRequest, Surface: "api", Method: "POST", Path: "/v1/trial-keys", UserAgent: ua, Status: 201}),
		step(0, events.Event{Kind: events.KindCanaryExposed, CanarySlot: "docs_sample_key"}),
		step(7*time.Second, events.Event{Kind: events.KindToolCall, Protocol: "mcp", Detail: map[string]any{"rpc_method": "initialize"}}),
		step(3*time.Second, events.Event{Kind: events.KindToolCall, Protocol: "mcp", Detail: map[string]any{"rpc_method": "tools/list"}}),
		step(9*time.Second, events.Event{Kind: events.KindToolCall, Protocol: "mcp", Detail: map[string]any{"rpc_method": "tools/call", "tool": "list_provider_keys"}}),
		step(0, events.Event{Kind: events.KindCanaryUsed, CanarySlot: "docs_sample_key"}),
		step(12*time.Second, events.Event{Kind: events.KindToolCall, Protocol: "mcp", Detail: map[string]any{"rpc_method": "tools/call", "tool": "get_provider_key"}}),
		step(0, events.Event{Kind: events.KindCanaryExposed, CanarySlot: "provider_key_vllm"}),
	}
}

func scannerRun(src string, n int) []events.Event {
	var evs []events.Event
	for i := 0; i < n; i++ {
		evs = append(evs, events.Event{Kind: events.KindRequest, Surface: "www", Method: "GET", Source: src,
			Path:      []string{"/.env", "/wp-login.php", "/.git/config", "/phpmyadmin/", "/actuator/env", "/server-status"}[i%6],
			UserAgent: "Mozilla/5.0 zgrab/0.x", Status: 404, Time: t0.Add(time.Duration(i) * 50 * time.Millisecond), Detail: map[string]any{}})
	}
	return evs
}

func build(runs map[string][]events.Event) ([]classify.Actor, []Cluster) {
	var actors []classify.Actor
	for src, evs := range runs {
		actors = append(actors, classify.Classify(src, evs))
	}
	slices.SortFunc(actors, func(a, b classify.Actor) int {
		if a.Source < b.Source {
			return -1
		}
		return 1
	})
	cs := Build(actors, runs)
	Assign(actors, cs)
	return actors, cs
}

func TestSameBehaviorClustersAcrossAddresses(t *testing.T) {
	runs := map[string][]events.Event{}
	for i := 0; i < 3; i++ {
		src := fmt.Sprintf("203.0.113.%d", 10+i)
		runs[src] = agentRun(src, time.Duration(i)*time.Hour)
	}
	// Four scanners: more than a tenth of the population shares their tokens.
	for i := 0; i < 4; i++ {
		src := fmt.Sprintf("198.51.100.%d", 10+i)
		runs[src] = scannerRun(src, 12)
	}
	actors, cs := build(runs)
	if len(cs) != 2 {
		t.Fatalf("want an agent family and a scanner family, got %+v", cs)
	}
	var agents Cluster
	for _, c := range cs {
		if slices.Contains(c.Classes, classify.RogueAgent) {
			agents = c
		}
	}
	if len(agents.Members) != 3 || !slices.Contains(agents.Classes, classify.RogueAgent) || agents.Cohesion < Threshold {
		t.Fatalf("agent family: %+v", agents)
	}
	if !slices.ContainsFunc(agents.Signature, func(s string) bool { return s == "canary_exposed:provider_key_vllm" }) {
		t.Fatalf("signature does not explain the family: %v", agents.Signature)
	}
	for _, a := range actors {
		if a.ClusterID == "" {
			t.Fatalf("%s not assigned", a.Source)
		}
	}
	// The same input gives the same IDs.
	_, again := build(runs)
	if again[0].ID != cs[0].ID || again[1].ID != cs[1].ID {
		t.Fatal("cluster IDs not stable")
	}
}

func TestTemplatesIgnoreIDs(t *testing.T) {
	if template("/v1/tasks/9f86d081884c7d65?x=1") != template("/v1/tasks/0a1b2c3d4e5f6071") {
		t.Fatal("hex IDs not templated")
	}
}
