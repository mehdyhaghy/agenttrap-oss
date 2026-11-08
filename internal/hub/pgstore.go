package hub

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"agenttrap/internal/correlate"
	"agenttrap/internal/events"
	"agenttrap/internal/worldpack"
)

//go:embed schema.sql
var schemaSQL string

// PGStore is the PostgreSQL-backed Store.
type PGStore struct {
	pool *pgxpool.Pool
}

// OpenPG connects to PostgreSQL and applies the schema.
func OpenPG(ctx context.Context, dsn string) (*PGStore, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	// timestamptz is stored as UTC; pinning the session keeps anything the
	// database derives from it (date_trunc buckets) in UTC as well, whatever
	// the server's own zone. Viewers see their local time in the dashboard.
	cfg.ConnConfig.RuntimeParams["timezone"] = "UTC"
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if _, err := pool.Exec(ctx, schemaSQL); err != nil {
		pool.Close()
		return nil, err
	}
	return &PGStore{pool: pool}, nil
}

func (s *PGStore) Close() { s.pool.Close() }

func (s *PGStore) CreateSpoke(ctx context.Context, id string, seed []byte) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO spokes (id, canary_seed) VALUES ($1, $2)`, id, seed)
	return err
}

func (s *PGStore) GetSpoke(ctx context.Context, id string) (Spoke, error) {
	var sp Spoke
	err := s.pool.QueryRow(ctx,
		`SELECT id, created_at, revoked, last_seen, canary_seed FROM spokes WHERE id = $1`, id).
		Scan(&sp.ID, &sp.CreatedAt, &sp.Revoked, &sp.LastSeen, &sp.CanarySeed)
	if errors.Is(err, pgx.ErrNoRows) {
		return Spoke{}, ErrNotFound
	}
	return sp, err
}

func (s *PGStore) ListSpokes(ctx context.Context) ([]Spoke, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, created_at, revoked, last_seen FROM spokes ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Spoke, error) {
		var sp Spoke
		err := r.Scan(&sp.ID, &sp.CreatedAt, &sp.Revoked, &sp.LastSeen)
		return sp, err
	})
}

func (s *PGStore) RevokeSpoke(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE spokes SET revoked = true WHERE id = $1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (s *PGStore) TouchSpoke(ctx context.Context, id string, at time.Time) error {
	_, err := s.pool.Exec(ctx, `UPDATE spokes SET last_seen = $2 WHERE id = $1`, id, at)
	return err
}

func (s *PGStore) CreateEnrollToken(ctx context.Context, hash, spokeID string, expires time.Time) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO enroll_tokens (token_sha256, spoke_id, expires_at) VALUES ($1, $2, $3)`, hash, spokeID, expires)
	return err
}

func (s *PGStore) ConsumeEnrollToken(ctx context.Context, hash string, now time.Time) (string, error) {
	var spokeID string
	err := s.pool.QueryRow(ctx,
		`UPDATE enroll_tokens SET used_at = $2
		  WHERE token_sha256 = $1 AND used_at IS NULL AND expires_at > $2
		  RETURNING spoke_id`, hash, now).Scan(&spokeID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	return spokeID, err
}

func (s *PGStore) AddCanaries(ctx context.Context, spokeID string, hashes map[string]string) error {
	b := &pgx.Batch{}
	for h, slot := range hashes {
		b.Queue(`INSERT INTO canaries (value_sha256, spoke_id, slot) VALUES ($1, $2, $3)
		         ON CONFLICT (value_sha256) DO NOTHING`, h, spokeID, slot)
	}
	return s.pool.SendBatch(ctx, b).Close()
}

func (s *PGStore) LookupCanary(ctx context.Context, hash string) (string, string, error) {
	var spokeID, slot string
	err := s.pool.QueryRow(ctx, `SELECT spoke_id, slot FROM canaries WHERE value_sha256 = $1`, hash).Scan(&spokeID, &slot)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", ErrNotFound
	}
	return spokeID, slot, err
}

func (s *PGStore) InsertEvents(ctx context.Context, evs []events.Event) ([]events.Event, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var fresh []events.Event
	for _, ev := range evs {
		detail, err := json.Marshal(ev.Detail)
		if err != nil {
			return nil, err
		}
		tag, err := tx.Exec(ctx,
			`INSERT INTO events (id, spoke_id, ts, protocol, surface, kind, source, user_agent,
			                     method, host, path, status, canary_slot, credential_sha256, detail)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
			 ON CONFLICT (id) DO NOTHING`,
			ev.ID, ev.SpokeID, ev.Time, ev.Protocol, ev.Surface, ev.Kind, ev.Source, ev.UserAgent,
			ev.Method, ev.Host, ev.Path, ev.Status, ev.CanarySlot, ev.CredentialSHA256, detail)
		if err != nil {
			return nil, err
		}
		if tag.RowsAffected() == 1 {
			fresh = append(fresh, ev)
		}
	}
	return fresh, tx.Commit(ctx)
}

func (s *PGStore) ListEvents(ctx context.Context, f EventFilter) ([]events.Event, error) {
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 100
	}
	var until any
	if !f.Until.IsZero() {
		until = f.Until
	}
	rows, err := s.pool.Query(ctx,
		`SELECT id, spoke_id, ts, protocol, surface, kind, source, user_agent, method, host, path,
		        status, canary_slot, credential_sha256, detail
		   FROM events
		  WHERE ($1 = '' OR source = $1) AND ($3 = '' OR kind = $3) AND ($4 = '' OR surface = $4)
		    AND ts >= $5 AND ($6::timestamptz IS NULL OR ts < $6)
		  ORDER BY ts DESC LIMIT $2`, f.Source, f.Limit, f.Kind, f.Surface, f.Since, until)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanEvent)
}

func scanEvent(r pgx.CollectableRow) (events.Event, error) {
	var ev events.Event
	var detail []byte
	err := r.Scan(&ev.ID, &ev.SpokeID, &ev.Time, &ev.Protocol, &ev.Surface, &ev.Kind, &ev.Source,
		&ev.UserAgent, &ev.Method, &ev.Host, &ev.Path, &ev.Status, &ev.CanarySlot, &ev.CredentialSHA256, &detail)
	if err == nil && len(detail) > 0 {
		err = json.Unmarshal(detail, &ev.Detail)
	}
	return ev, err
}

func (s *PGStore) WasExposed(ctx context.Context, source, originSpoke, slot string) (bool, error) {
	var ok bool
	err := s.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM events WHERE kind = 'canary_exposed'
		                  AND source = $1 AND spoke_id = $2 AND canary_slot = $3)`,
		source, originSpoke, slot).Scan(&ok)
	return ok, err
}

const incidentCols = `id, source, spokes, first_seen, last_seen, stages, score, severity, cross_spoke, out_of_band, relayed`

func scanIncident(r pgx.Row) (correlate.Incident, error) {
	var inc correlate.Incident
	var stages []int32
	err := r.Scan(&inc.ID, &inc.Source, &inc.Spokes, &inc.FirstSeen, &inc.LastSeen, &stages,
		&inc.Score, &inc.Severity, &inc.CrossSpoke, &inc.OutOfBand, &inc.Relayed)
	for _, s := range stages {
		inc.Stages = append(inc.Stages, int(s))
	}
	return inc, err
}

func (s *PGStore) IncidentBySource(ctx context.Context, source string) (*correlate.Incident, error) {
	inc, err := scanIncident(s.pool.QueryRow(ctx, `SELECT `+incidentCols+` FROM incidents WHERE source = $1`, source))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &inc, nil
}

func (s *PGStore) SaveIncident(ctx context.Context, inc *correlate.Incident) error {
	stages := make([]int32, len(inc.Stages))
	for i, v := range inc.Stages {
		stages[i] = int32(v)
	}
	return s.pool.QueryRow(ctx,
		`INSERT INTO incidents (source, spokes, first_seen, last_seen, stages, score, severity, cross_spoke, out_of_band, relayed)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		 ON CONFLICT (source) DO UPDATE SET spokes = EXCLUDED.spokes, first_seen = EXCLUDED.first_seen,
		   last_seen = EXCLUDED.last_seen, stages = EXCLUDED.stages, score = EXCLUDED.score,
		   severity = EXCLUDED.severity, cross_spoke = EXCLUDED.cross_spoke, out_of_band = EXCLUDED.out_of_band,
		   relayed = EXCLUDED.relayed
		 RETURNING id`,
		inc.Source, inc.Spokes, inc.FirstSeen, inc.LastSeen, stages, inc.Score, inc.Severity,
		inc.CrossSpoke, inc.OutOfBand, inc.Relayed).Scan(&inc.ID)
}

func (s *PGStore) ListIncidents(ctx context.Context, limit int) ([]correlate.Incident, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `SELECT `+incidentCols+` FROM incidents ORDER BY last_seen DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (correlate.Incident, error) { return scanIncident(r) })
}

// Overview computes the dashboard summary in SQL.
func (s *PGStore) Overview(ctx context.Context, since time.Time, chain []worldpack.ChainStep, exclude []netip.Prefix) (Overview, error) {
	o := Overview{Since: since, Severity: map[string]int{}}
	ex := prefixStrings(exclude)
	err := s.pool.QueryRow(ctx, `
		SELECT count(*),
		       count(*) FILTER (WHERE kind = 'request'),
		       count(DISTINCT source),
		       count(*) FILTER (WHERE kind = 'tls_hello'),
		       count(DISTINCT detail->>'ja4') FILTER (WHERE kind = 'tls_hello'),
		       count(*) FILTER (WHERE kind = 'canary_used')
		  FROM events WHERE ts >= $1 AND `+notOperator("$2"), since, ex).
		Scan(&o.Totals.Events, &o.Totals.Requests, &o.Totals.Sources, &o.Totals.TLSHellos,
			&o.Totals.Fingerprints, &o.Totals.CanaryUses)
	if err != nil {
		return o, err
	}

	rows, err := s.pool.Query(ctx, `SELECT severity, count(*) FROM incidents WHERE last_seen >= $1 AND `+notOperator("$2")+` GROUP BY 1`, since, ex)
	if err != nil {
		return o, err
	}
	for rows.Next() {
		var sev string
		var n int
		if err := rows.Scan(&sev, &n); err != nil {
			rows.Close()
			return o, err
		}
		o.Severity[sev] = n
	}
	rows.Close()

	for _, st := range chain {
		var n int
		if err := s.pool.QueryRow(ctx,
			`SELECT count(DISTINCT source) FROM events WHERE ts >= $1 AND kind = $2 AND canary_slot = $3
			   AND NOT (detail ? 'module' OR detail ? 'exposed_by') AND `+notOperator("$4"),
			since, st.Kind, st.Slot, ex).Scan(&n); err != nil {
			return o, err
		}
		o.Funnel = append(o.Funnel, FunnelStage{Stage: st.Stage, Name: st.Name, Sources: n})
	}

	collect := func(q string, scan func(pgx.CollectableRow) error) error {
		rows, err := s.pool.Query(ctx, q, since, topN, ex)
		if err != nil {
			return err
		}
		_, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (struct{}, error) { return struct{}{}, scan(r) })
		return err
	}
	if err := collect(`
		SELECT date_trunc('hour', ts), count(*), count(DISTINCT source)
		  FROM events WHERE ts >= $1 AND kind = 'request' AND $2 > 0 AND `+notOperator("$3")+` GROUP BY 1 ORDER BY 1`,
		func(r pgx.CollectableRow) error {
			var b TimeBucket
			err := r.Scan(&b.Time, &b.Requests, &b.Sources)
			o.Timeline = append(o.Timeline, b)
			return err
		}); err != nil {
		return o, err
	}
	if err := collect(`
		SELECT source, count(*), max(ts),
		       coalesce((array_agg(user_agent ORDER BY ts DESC) FILTER (WHERE user_agent <> ''))[1], '')
		  FROM events WHERE ts >= $1 AND `+notOperator("$3")+` GROUP BY source ORDER BY 2 DESC, 1 LIMIT $2`,
		func(r pgx.CollectableRow) error {
			var v SourceStat
			err := r.Scan(&v.Source, &v.Events, &v.LastSeen, &v.UserAgent)
			o.TopSources = append(o.TopSources, v)
			return err
		}); err != nil {
		return o, err
	}
	if err := collect(`
		SELECT detail->>'ja4', count(DISTINCT source), count(*),
		       coalesce((array_agg(user_agent ORDER BY ts DESC))[1], '')
		  FROM events WHERE ts >= $1 AND kind = 'request' AND detail ? 'ja4' AND `+notOperator("$3")+`
		 GROUP BY 1 ORDER BY 2 DESC, 3 DESC, 1 LIMIT $2`,
		func(r pgx.CollectableRow) error {
			var v Fingerprint
			err := r.Scan(&v.JA4, &v.Sources, &v.Requests, &v.UserAgent)
			o.TopFingerprints = append(o.TopFingerprints, v)
			return err
		}); err != nil {
		return o, err
	}
	if err := collect(`
		SELECT user_agent, count(*), count(DISTINCT source)
		  FROM events WHERE ts >= $1 AND kind = 'request' AND `+notOperator("$3")+` GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT $2`,
		func(r pgx.CollectableRow) error {
			var v UserAgent
			err := r.Scan(&v.UserAgent, &v.Requests, &v.Sources)
			o.TopUserAgents = append(o.TopUserAgents, v)
			return err
		}); err != nil {
		return o, err
	}
	if err := collect(`
		SELECT surface, split_part(path, '?', 1), count(*), count(DISTINCT source)
		  FROM events WHERE ts >= $1 AND kind = 'request' AND `+notOperator("$3")+` GROUP BY 1, 2 ORDER BY 3 DESC, 2 LIMIT $2`,
		func(r pgx.CollectableRow) error {
			var v PathStat
			err := r.Scan(&v.Surface, &v.Path, &v.Requests, &v.Sources)
			o.TopPaths = append(o.TopPaths, v)
			return err
		}); err != nil {
		return o, err
	}
	// $2 (topN) is unused: every module's attack is listed.
	if err := collect(`
		SELECT coalesce(detail->>'module', ''), coalesce(detail->>'attack', ''),
		       count(*) FILTER (WHERE detail->>'stage' = 'exploit'),
		       count(*) FILTER (WHERE detail->>'stage' IS DISTINCT FROM 'exploit'),
		       count(DISTINCT source), max(ts),
		       coalesce(jsonb_agg(DISTINCT detail->'cve') FILTER (WHERE jsonb_typeof(detail->'cve') = 'array'), '[]'::jsonb)
		  FROM events WHERE ts >= $1 AND kind = 'exploit' AND $2 > 0 AND `+notOperator("$3")+` GROUP BY 1, 2`,
		func(r pgx.CollectableRow) error {
			var v ExploitStat
			var raw []byte
			if err := r.Scan(&v.Module, &v.Attack, &v.Attempts, &v.Probes, &v.Sources, &v.LastSeen, &raw); err != nil {
				return err
			}
			var lists [][]string
			if err := json.Unmarshal(raw, &lists); err != nil {
				return err
			}
			v.CVEs = slices.Compact(slices.Sorted(slices.Values(slices.Concat(lists...))))
			o.Exploits = append(o.Exploits, v)
			return nil
		}); err != nil {
		return o, err
	}
	sortExploits(o.Exploits)
	return o, nil
}

func (s *PGStore) EventsSince(ctx context.Context, since time.Time, limit int) ([]events.Event, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, spoke_id, ts, protocol, surface, kind, source, user_agent, method, host, path,
		        status, canary_slot, credential_sha256, detail
		   FROM events WHERE ts >= $1 ORDER BY source, ts LIMIT $2`, since, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanEvent)
}

func (s *PGStore) EventsBetween(ctx context.Context, from, to time.Time, limit int) ([]events.Event, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, spoke_id, ts, protocol, surface, kind, source, user_agent, method, host, path,
		        status, canary_slot, credential_sha256, detail
		   FROM events WHERE ts >= $1 AND ts < $2 ORDER BY source, ts LIMIT $3`, from, to, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanEvent)
}

func (s *PGStore) OldestEvent(ctx context.Context) (time.Time, error) {
	var t *time.Time
	if err := s.pool.QueryRow(ctx, `SELECT min(ts) FROM events`).Scan(&t); err != nil || t == nil {
		return time.Time{}, err
	}
	return *t, nil
}

func (s *PGStore) FindExposure(ctx context.Context, id string) (events.Event, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, spoke_id, ts, protocol, surface, kind, source, user_agent, method, host, path,
		        status, canary_slot, credential_sha256, detail
		   FROM events WHERE kind = 'canary_exposed' AND detail->>'exposure_id' = $1 LIMIT 1`, id)
	if err != nil {
		return events.Event{}, err
	}
	evs, err := pgx.CollectRows(rows, scanEvent)
	if err != nil {
		return events.Event{}, err
	}
	if len(evs) == 0 {
		return events.Event{}, ErrNotFound
	}
	return evs[0], nil
}

// notOperator is a SQL condition excluding sources inside the CIDR array
// parameter p. Pseudonymized sources are not addresses and never match; the
// CASE keeps Postgres from casting them to inet.
func notOperator(p string) string {
	return `NOT (CASE WHEN source ~ '^[0-9a-fA-F.:]+$' THEN source::inet <<= ANY(` + p + `::inet[]) ELSE false END)`
}

func prefixStrings(ps []netip.Prefix) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.String())
	}
	return out
}

func (s *PGStore) ListOperators(ctx context.Context) ([]Operator, error) {
	rows, err := s.pool.Query(ctx, `SELECT cidr, note, created_at FROM operators ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Operator, error) {
		var o Operator
		err := r.Scan(&o.CIDR, &o.Note, &o.CreatedAt)
		return o, err
	})
}

func (s *PGStore) AddOperator(ctx context.Context, o Operator) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO operators (cidr, note) VALUES ($1, $2)
		ON CONFLICT (cidr) DO UPDATE SET note = EXCLUDED.note`, o.CIDR, o.Note)
	return err
}

func (s *PGStore) RemoveOperator(ctx context.Context, cidr string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM operators WHERE cidr = $1`, cidr)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (s *PGStore) DeleteIncidentsIn(ctx context.Context, prefix netip.Prefix) (int, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM incidents WHERE NOT `+notOperator("$1"), []string{prefix.String()})
	return int(tag.RowsAffected()), err
}

func (s *PGStore) SaveRDNS(ctx context.Context, r SourceRDNS) error {
	if r.Hostnames == nil {
		r.Hostnames = []string{}
	}
	if r.Confirmed == nil {
		r.Confirmed = []string{}
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO source_rdns (source, hostnames, confirmed, checked_at, error)
		VALUES ($1, $2, $3, now(), $4)
		ON CONFLICT (source) DO UPDATE SET hostnames = EXCLUDED.hostnames, confirmed = EXCLUDED.confirmed,
		  checked_at = EXCLUDED.checked_at, error = EXCLUDED.error`, r.Source, r.Hostnames, r.Confirmed, r.Error)
	return err
}

func (s *PGStore) RDNSFor(ctx context.Context, sources []string) (map[string]SourceRDNS, error) {
	rows, err := s.pool.Query(ctx, `SELECT source, hostnames, confirmed, checked_at, error FROM source_rdns WHERE source = ANY($1)`, sources)
	if err != nil {
		return nil, err
	}
	list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (SourceRDNS, error) {
		var v SourceRDNS
		err := r.Scan(&v.Source, &v.Hostnames, &v.Confirmed, &v.CheckedAt, &v.Error)
		return v, err
	})
	out := make(map[string]SourceRDNS, len(list))
	for _, v := range list {
		out[v.Source] = v
	}
	return out, err
}

func (s *PGStore) SaveReplayChunks(ctx context.Context, chunks []ReplayChunk) error {
	b := &pgx.Batch{}
	for _, c := range chunks {
		b.Queue(`INSERT INTO replay_chunks (view_id, seq, spoke_id, source, surface, ts, data)
			VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (view_id, seq) DO NOTHING`,
			c.ViewID, c.Seq, c.SpokeID, c.Source, c.Surface, c.Time, []byte(c.Data))
	}
	return s.pool.SendBatch(ctx, b).Close()
}

func (s *PGStore) ListReplays(ctx context.Context, source string, limit int) ([]ReplaySummary, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `
		SELECT view_id, min(source), min(surface), min(ts), max(ts), count(*), sum(length(data::text))
		  FROM replay_chunks WHERE ($1 = '' OR source = $1)
		 GROUP BY view_id ORDER BY max(ts) DESC LIMIT $2`, source, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (ReplaySummary, error) {
		var v ReplaySummary
		err := r.Scan(&v.ViewID, &v.Source, &v.Surface, &v.Start, &v.End, &v.Chunks, &v.Bytes)
		return v, err
	})
}

func (s *PGStore) GetReplay(ctx context.Context, viewID string) ([]json.RawMessage, error) {
	rows, err := s.pool.Query(ctx, `SELECT data FROM replay_chunks WHERE view_id = $1 ORDER BY seq`, viewID)
	if err != nil {
		return nil, err
	}
	chunks, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) ([]byte, error) {
		var b []byte
		err := r.Scan(&b)
		return b, err
	})
	if err != nil {
		return nil, err
	}
	return flattenChunks(chunks)
}

// isDataError reports whether err is Postgres refusing the data itself
// (SQLSTATE class 22, data exception), which retrying cannot fix.
func isDataError(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && strings.HasPrefix(pgErr.Code, "22")
}

func (s *PGStore) SourceActivity(ctx context.Context, since, until time.Time, step time.Duration) ([]SourceBucket, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT source, date_bin(make_interval(secs => $3), ts, $1), count(*)
		  FROM events WHERE ts >= $1 AND ts < $2
		 GROUP BY 1, 2`, since, until, step.Seconds())
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (SourceBucket, error) {
		var b SourceBucket
		err := r.Scan(&b.Source, &b.Start, &b.Events)
		return b, err
	})
}
