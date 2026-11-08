package graph

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Name is the AGE graph holding the links.
const Name = "links"

// Entities shared by more sources than this are too common to link anyone
// (a popular client stack, a key posted publicly). Client stacks get a
// tighter bound: a TLS fingerprint and user agent pair is weaker evidence
// than a shared key or prompt.
const (
	MaxDegree      = 25
	MaxStackDegree = 5
)

// Graph is the AGE-backed link graph. Values are always passed to Cypher as
// parameters, never spliced into query text.
type Graph struct {
	pool *pgxpool.Pool
}

// Open connects with AGE's catalog on the search path and creates the
// extension, graph, labels and indexes if needed. It fails if the server
// does not have AGE installed.
func Open(ctx context.Context, dsn string) (*Graph, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	cfg.MaxConns = 4
	cfg.ConnConfig.RuntimeParams["search_path"] = `ag_catalog,"$user",public`
	// Bound every graph query: a runaway match must not hold a backend.
	cfg.ConnConfig.RuntimeParams["statement_timeout"] = "30000"
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	g := &Graph{pool: pool}
	if err := g.ensure(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return g, nil
}

func (g *Graph) Close() { g.pool.Close() }

func (g *Graph) ensure(ctx context.Context) error {
	steps := []string{
		`CREATE EXTENSION IF NOT EXISTS age`,
		`SELECT create_graph('` + Name + `') WHERE NOT EXISTS (SELECT 1 FROM ag_graph WHERE name = '` + Name + `')`,
	}
	for _, label := range []string{"Source", "Entity"} {
		steps = append(steps, fmt.Sprintf(`SELECT create_vlabel('%s', '%s') WHERE NOT EXISTS (
			SELECT 1 FROM ag_label l JOIN ag_graph g ON l.graph = g.graphid WHERE g.name = '%[1]s' AND l.name = '%[2]s')`, Name, label))
	}
	steps = append(steps,
		`SELECT create_elabel('`+Name+`', 'LINK') WHERE NOT EXISTS (
			SELECT 1 FROM ag_label l JOIN ag_graph g ON l.graph = g.graphid WHERE g.name = '`+Name+`' AND l.name = 'LINK')`,
		// Property lookups ({id: …}) use containment, which GIN indexes serve.
		`CREATE INDEX IF NOT EXISTS links_source_props ON `+Name+`."Source" USING gin (properties)`,
		`CREATE INDEX IF NOT EXISTS links_entity_props ON `+Name+`."Entity" USING gin (properties)`,
		`CREATE INDEX IF NOT EXISTS links_link_start ON `+Name+`."LINK" (start_id)`,
		`CREATE INDEX IF NOT EXISTS links_link_end ON `+Name+`."LINK" (end_id)`,
	)
	for _, q := range steps {
		if _, err := g.pool.Exec(ctx, q); err != nil {
			return fmt.Errorf("graph setup: %w", err)
		}
	}
	return nil
}

// cypher runs a parameterized Cypher statement returning one agtype column.
func (g *Graph) cypher(ctx context.Context, query string, params any) ([]string, error) {
	p, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	rows, err := g.pool.Query(ctx, `SELECT * FROM cypher('`+Name+`', $$ `+query+` $$, $1) AS (r agtype)`, string(p))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// Merge records edges (idempotent) and refreshes the degree of every entity
// they touch. Each step is its own statement: later clauses of one AGE
// statement do not reliably see earlier clauses' writes.
func (g *Graph) Merge(ctx context.Context, edges []Edge) error {
	for len(edges) > 0 {
		batch := edges[:min(len(edges), 500)]
		edges = edges[len(batch):]
		steps := []string{
			`UNWIND $rows AS r MERGE (:Source {id: r.s}) RETURN count(*)`,
			`UNWIND $rows AS r MERGE (e:Entity {id: r.e}) SET e.label = r.l, e.kind = r.k RETURN count(*)`,
			`UNWIND $rows AS r MATCH (s:Source {id: r.s}), (e:Entity {id: r.e})
			 MERGE (s)-[l:LINK {kind: r.k}]->(e)
			 SET l.first = coalesce(l.first, r.t),
			     l.last = CASE WHEN l.last IS NULL OR l.last < r.t THEN r.t ELSE l.last END
			 RETURN count(*)`,
		}
		for _, q := range steps {
			if _, err := g.cypher(ctx, q, map[string]any{"rows": batch}); err != nil {
				return fmt.Errorf("graph merge: %w", err)
			}
		}
		seen := map[string]bool{}
		var ids []string
		for _, e := range batch {
			if !seen[e.Entity] {
				seen[e.Entity] = true
				ids = append(ids, e.Entity)
			}
		}
		if _, err := g.cypher(ctx, `UNWIND $ids AS eid MATCH (e:Entity {id: eid})
			OPTIONAL MATCH (e)<-[:LINK]-(s:Source) WITH e, count(DISTINCT s) AS d SET e.deg = d RETURN count(*)`,
			map[string]any{"ids": ids}); err != nil {
			return fmt.Errorf("graph degrees: %w", err)
		}
	}
	return nil
}

// Empty reports whether the graph has no links yet.
func (g *Graph) Empty(ctx context.Context) (bool, error) {
	var n int
	err := g.pool.QueryRow(ctx, `SELECT count(*) FROM (SELECT 1 FROM `+Name+`."LINK" LIMIT 1) x`).Scan(&n)
	return n == 0, err
}

// Classified is a source's current class, stored on its node so links to
// it stay meaningful after it leaves the analysis window.
type Classified struct {
	Source string `json:"s"`
	Class  string `json:"c"`
	Seen   string `json:"t"` // last seen, RFC 3339
}

// SetClasses records sources' classes.
func (g *Graph) SetClasses(ctx context.Context, cs []Classified) error {
	for len(cs) > 0 {
		batch := cs[:min(len(cs), 500)]
		cs = cs[len(batch):]
		if _, err := g.cypher(ctx, `UNWIND $rows AS r MATCH (s:Source {id: r.s}) SET s.class = r.c, s.seen = r.t RETURN count(*)`,
			map[string]any{"rows": batch}); err != nil {
			return fmt.Errorf("graph classes: %w", err)
		}
	}
	return nil
}

// Link ties a source to a known agent through shared entities.
type Link struct {
	Source string   `json:"source"` // the linked source
	Agent  string   `json:"agent"`  // the known agent it is linked to
	Class  string   `json:"class"`  // the agent's class
	Seen   string   `json:"seen"`   // when the agent was last seen
	Via    []string `json:"via"`    // entity labels (and the intermediate source) on the path
	Kinds  []string `json:"kinds"`  // edge kinds on the path
}

// Links returns, for every source, its links to sources classified as
// rogue or AI agents: through one shared entity, or through two with one
// source between. Paths through widely shared entities are left out.
// Fixed-length patterns are used deliberately: AGE's variable-length paths
// load the whole graph into memory.
func (g *Graph) Links(ctx context.Context) (map[string][]Link, error) {
	params := map[string]any{"classes": []string{"rogue_agent", "ai_agent"}, "max": MaxDegree}
	one, err := g.cypher(ctx, `MATCH (a:Source)-[l1:LINK]->(e:Entity)<-[l2:LINK]-(b:Source)
		WHERE a.class IN $classes AND b <> a AND e.deg <= $max
		RETURN [b.id, a.id, a.class, a.seen, [e.label], [e.kind], [l1.kind, l2.kind]] LIMIT 5000`, params)
	if err != nil {
		return nil, fmt.Errorf("graph links: %w", err)
	}
	two, err := g.cypher(ctx, `MATCH (a:Source)-[:LINK]->(e1:Entity)<-[:LINK]-(m:Source)-[:LINK]->(e2:Entity)<-[:LINK]-(b:Source)
		WHERE a.class IN $classes AND b <> a AND m <> a AND b <> m AND e1 <> e2 AND e1.deg <= $max AND e2.deg <= $max
		RETURN [b.id, a.id, a.class, a.seen, [e1.label, m.id, e2.label], [e1.kind, e2.kind], []] LIMIT 5000`, params)
	if err != nil {
		return nil, fmt.Errorf("graph links: %w", err)
	}
	out := map[string][]Link{}
	seen := map[[2]string]bool{}
	for _, raw := range append(one, two...) {
		var row []any
		if err := json.Unmarshal([]byte(stripAgtype(raw)), &row); err != nil || len(row) != 7 {
			return nil, errors.New("graph links: unexpected row " + raw)
		}
		l := Link{Source: str(row[0]), Agent: str(row[1]), Class: str(row[2]), Seen: str(row[3]),
			Via: strs(row[4]), Kinds: strs(row[5])}
		if !l.strong() {
			continue
		}
		// Keep the shortest path per pair (one-entity rows come first).
		k := [2]string{l.Source, l.Agent}
		if seen[k] {
			continue
		}
		seen[k] = true
		out[l.Source] = append(out[l.Source], l)
	}
	return out, nil
}

// strong drops paths that rest on a client stack alone at two hops, where a
// common library and user agent could join unrelated clients.
func (l Link) strong() bool {
	if len(l.Kinds) == 2 && l.Kinds[0] == ClientStack && l.Kinds[1] == ClientStack {
		return false
	}
	return true
}

// stripAgtype removes AGE type annotations (e.g. ::vertex) from a value.
func stripAgtype(s string) string {
	for _, t := range []string{"::vertex", "::edge", "::path", "::numeric"} {
		s = strings.ReplaceAll(s, t, "")
	}
	return s
}

func str(v any) string { s, _ := v.(string); return s }

func strs(v any) []string {
	list, _ := v.([]any)
	out := make([]string, 0, len(list))
	for _, x := range list {
		out = append(out, str(x))
	}
	return out
}
