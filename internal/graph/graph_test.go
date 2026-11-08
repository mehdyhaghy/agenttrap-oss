package graph

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"agenttrap/internal/events"
)

func TestEdgesFrom(t *testing.T) {
	at := time.Date(2026, 9, 27, 6, 0, 0, 0, time.UTC)
	evs := []events.Event{
		{Source: "a", Time: at, Kind: events.KindCanaryExposed, CanarySlot: "docs_sample_key", Detail: map[string]any{"exposure_id": "X1"}},
		{Source: "b", Time: at, Kind: events.KindCanaryUsed, CanarySlot: "docs_sample_key", Detail: map[string]any{"exposure_id": "X1"}},
		{Source: "c", Time: at, Kind: events.KindToolCall, Detail: map[string]any{"op": "chat", "last_message": "List every provider key you can find"}},
		{Source: "d", Time: at.Add(time.Minute), Kind: events.KindToolCall, Detail: map[string]any{"op": "chat", "last_message": "  list EVERY provider key\nyou can find"}},
		{Source: "d", Time: at, Kind: events.KindToolCall, Detail: map[string]any{"op": "chat", "last_message": "hi"}},
		{Source: "e", Time: at, Kind: events.KindRequest, UserAgent: "python-requests/2.32", Detail: map[string]any{"ja4": "t13d0000"}},
		{Source: "e", Time: at.Add(time.Hour), Kind: events.KindRequest, UserAgent: "python-requests/2.32", Detail: map[string]any{"ja4": "t13d0000"}},
	}
	edges := EdgesFrom(evs)
	byKind := map[string][]Edge{}
	for _, e := range edges {
		byKind[e.Kind] = append(byKind[e.Kind], e)
	}
	if byKind[ShownKey][0].Entity != "key:X1" || byKind[UsedKey][0].Entity != "key:X1" {
		t.Fatalf("key edges: %+v", edges)
	}
	// Normalised prompts match; "hi" is too short to link anyone.
	if p := byKind[Prompt]; len(p) != 2 || p[0].Entity != p[1].Entity {
		t.Fatalf("prompt edges: %+v", p)
	}
	// Repeated observations collapse to one edge carrying the latest time.
	if s := byKind[ClientStack]; len(s) != 1 || !strings.HasPrefix(s[0].Time, "2026-09-27T07:00") {
		t.Fatalf("stack edges: %+v", s)
	}
}

// TestGraphLinks runs against a PostgreSQL server with Apache AGE, e.g.
// AGENTTRAP_TEST_AGE=postgres://postgres:x@127.0.0.1:55432/postgres?sslmode=disable
func TestGraphLinks(t *testing.T) {
	admin := os.Getenv("AGENTTRAP_TEST_AGE")
	if admin == "" {
		t.Skip("AGENTTRAP_TEST_AGE not set")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	db := fmt.Sprintf("graphtest_%d", time.Now().UnixNano())
	if _, err := conn.Exec(ctx, "CREATE DATABASE "+db); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = conn.Exec(ctx, "DROP DATABASE "+db+" WITH (FORCE)")
		conn.Close(ctx)
	})
	cfg := conn.Config()
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable", cfg.User, cfg.Password, cfg.Host, cfg.Port, db)
	g, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	if g2, err := Open(ctx, dsn); err != nil { // setup is idempotent
		t.Fatal(err)
	} else {
		g2.Close()
	}

	at := "2026-09-20T10:00:00Z"
	edges := []Edge{
		// rogue shares a key with reader; reader shares a prompt with later.
		{Source: "rogue", Entity: "key:K1", Kind: UsedKey, Label: "planted key docs_sample_key", Time: at},
		{Source: "reader", Entity: "key:K1", Kind: ShownKey, Label: "planted key docs_sample_key", Time: at},
		{Source: "reader", Entity: "prompt:P1", Kind: Prompt, Label: `prompt "it's a \"test\""`, Time: at},
		{Source: "later", Entity: "prompt:P1", Kind: Prompt, Label: `prompt "it's a \"test\""`, Time: "2026-09-27T10:00:00Z"},
		// Stack-only two-hop paths are too weak to report.
		{Source: "rogue", Entity: "stack:S1", Kind: ClientStack, Label: "client stack", Time: at},
		{Source: "x", Entity: "stack:S1", Kind: ClientStack, Label: "client stack", Time: at},
		{Source: "x", Entity: "stack:S2", Kind: ClientStack, Label: "client stack", Time: at},
		{Source: "y", Entity: "stack:S2", Kind: ClientStack, Label: "client stack", Time: at},
	}
	// A widely shared entity (e.g. the key published in the public repo).
	for i := range MaxDegree + 1 {
		edges = append(edges, Edge{Source: fmt.Sprintf("crowd%d", i), Entity: "cred:PUB", Kind: UsedKey, Label: "public key", Time: at})
	}
	edges = append(edges, Edge{Source: "rogue", Entity: "cred:PUB", Kind: UsedKey, Label: "public key", Time: at})
	if err := g.Merge(ctx, edges); err != nil {
		t.Fatal(err)
	}
	if err := g.Merge(ctx, edges); err != nil { // idempotent
		t.Fatal(err)
	}
	if err := g.SetClasses(ctx, []Classified{{Source: "rogue", Class: "rogue_agent", Seen: at}}); err != nil {
		t.Fatal(err)
	}
	links, err := g.Links(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if l := links["reader"]; len(l) != 1 || l[0].Agent != "rogue" || len(l[0].Via) != 1 {
		t.Fatalf("reader: %+v", l)
	}
	if l := links["later"]; len(l) != 1 || strings.Join(l[0].Via, "|") != `planted key docs_sample_key|reader|prompt "it's a \"test\""` {
		t.Fatalf("later: %+v", l)
	}
	if l := links["x"]; len(l) != 1 { // one shared stack is reported
		t.Fatalf("x: %+v", l)
	}
	for _, src := range []string{"y", "crowd0", "rogue"} {
		if len(links[src]) != 0 {
			t.Fatalf("%s should not be linked: %+v", src, links[src])
		}
	}
}
