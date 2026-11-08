// Package hub implements the private control plane: spoke enrollment and
// certificate renewal, event ingest, canary correlation and the admin API.
package hub

import (
	"cmp"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"agenttrap/internal/canary"
	"agenttrap/internal/classify"
	"agenttrap/internal/correlate"
	"agenttrap/internal/dashboard"
	"agenttrap/internal/events"
	"agenttrap/internal/export"
	"agenttrap/internal/geo"
	"agenttrap/internal/pki"
	"agenttrap/internal/protocol"
	"agenttrap/internal/rdns"
	"agenttrap/internal/worldpack"
)

// Config configures a Hub.
type Config struct {
	HubURL       string        // URL spokes use to reach the hub, e.g. https://hub:8443
	ServerNames  []string      // DNS names on the hub server certificate
	AdminToken   string        // bearer token for the admin API
	SpokeCertTTL time.Duration // lifetime of spoke client certificates
	ResolverURL  string        // optional reverse-DNS resolver, e.g. http://resolver:8053
	Operators    []string      // operator CIDRs or IPs to seed (from the environment)
	Producer     string        // name of the producing system in STIX exports
	DNSBLZone    string        // zone name used in the DNSBL export
	EnrollTTL    time.Duration // lifetime of enrollment tokens
}

// Hub is the control plane.
type Hub struct {
	cfg     Config
	store   Store
	issuer  *pki.Issuer
	pack    *worldpack.Pack
	packEnv worldpack.Envelope
	log     *slog.Logger

	corrMu sync.Mutex // serializes incident updates

	certMu     sync.Mutex
	serverCert *tls.Certificate

	seedMu  sync.Mutex
	seeds   map[string][]byte
	seedsAt time.Time

	rdnsMu    sync.Mutex
	rdnsCache map[string]rdnsEntry

	opMu      sync.RWMutex
	operators []netip.Prefix

	enrichQ    chan string
	started    time.Time
	ingMu      sync.Mutex
	ingest     map[string]*spokeIngest // spoke ID -> shipping health
	enrichSeen sync.Map                // source -> struct{}: already queued or stored this run

	graph   Linker // nil without the graph extension
	linkMu  sync.RWMutex
	links   map[string][]classify.Link // source -> links, refreshed by RunGraph
	linksAt time.Time

	geo *geo.DB // nil without a mounted geolocation database
}

type rdnsEntry struct {
	res rdns.Result
	at  time.Time
}

// New creates a hub serving packRaw to its spokes.
func New(cfg Config, store Store, issuer *pki.Issuer, packRaw []byte, log *slog.Logger) (*Hub, error) {
	pack, err := worldpack.Parse(packRaw)
	if err != nil {
		return nil, err
	}
	if cfg.SpokeCertTTL == 0 {
		cfg.SpokeCertTTL = 48 * time.Hour
	}
	if cfg.EnrollTTL == 0 {
		cfg.EnrollTTL = time.Hour
	}
	if cfg.Producer == "" {
		cfg.Producer = "agenttrap"
	}
	if cfg.DNSBLZone == "" {
		cfg.DNSBLZone = "dnsbl.invalid"
	}
	if len(cfg.AdminToken) < 24 {
		return nil, errors.New("hub: admin token must be at least 24 characters")
	}
	return &Hub{cfg: cfg, store: store, issuer: issuer, pack: pack,
		packEnv: worldpack.Sign(issuer.PackKey, packRaw), log: log, enrichQ: make(chan string, 4096),
		started: time.Now()}, nil
}

// SpokeTLSConfig is the TLS config for the spoke-facing listener. Client
// certificates are verified when presented; each route decides whether one is
// required (only enrollment is allowed without one).
func (h *Hub) SpokeTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS13,
		ClientAuth:     tls.VerifyClientCertIfGiven,
		ClientCAs:      h.issuer.Roots,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return h.currentServerCert() },
	}
}

func (h *Hub) currentServerCert() (*tls.Certificate, error) {
	h.certMu.Lock()
	defer h.certMu.Unlock()
	const ttl = 72 * time.Hour
	if h.serverCert == nil || time.Until(h.serverCert.Leaf.NotAfter) < ttl/3 {
		c, err := h.issuer.ServerCert(h.cfg.ServerNames, ttl)
		if err != nil {
			return nil, err
		}
		h.serverCert = c
	}
	return h.serverCert, nil
}

// SpokeHandler serves the mTLS spoke API.
func (h *Hub) SpokeHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/enroll", h.handleEnroll)
	mux.HandleFunc("POST /v1/renew", h.requireSpoke(h.handleRenew))
	mux.HandleFunc("GET /v1/config", h.requireSpoke(h.handleConfig))
	mux.HandleFunc("POST /v1/events", h.requireSpoke(h.handleEvents))
	return mux
}

type spokeHandler func(w http.ResponseWriter, r *http.Request, spokeID string)

func (h *Hub) requireSpoke(next spokeHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			http.Error(w, "client certificate required", http.StatusUnauthorized)
			return
		}
		id, ok := pki.SpokeID(r.TLS.VerifiedChains[0][0])
		if !ok {
			http.Error(w, "not a spoke certificate", http.StatusForbidden)
			return
		}
		sp, err := h.store.GetSpoke(r.Context(), id)
		if err != nil || sp.Revoked {
			http.Error(w, "spoke not authorized", http.StatusForbidden)
			return
		}
		_ = h.store.TouchSpoke(r.Context(), id, time.Now())
		next(w, r, id)
	}
}

func (h *Hub) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var req protocol.EnrollRequest
	if err := decode(r, &req, 64<<10); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	spokeID, err := h.store.ConsumeEnrollToken(r.Context(), hashToken(req.Token), time.Now())
	if err != nil {
		h.log.Warn("enrollment rejected", "remote", r.RemoteAddr)
		http.Error(w, "invalid or expired token", http.StatusUnauthorized)
		return
	}
	h.issue(w, r, spokeID, req.CSRPEM)
}

func (h *Hub) handleRenew(w http.ResponseWriter, r *http.Request, spokeID string) {
	var req protocol.RenewRequest
	if err := decode(r, &req, 64<<10); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	h.issue(w, r, spokeID, req.CSRPEM)
}

func (h *Hub) issue(w http.ResponseWriter, r *http.Request, spokeID, csrPEM string) {
	sp, err := h.store.GetSpoke(r.Context(), spokeID)
	if err != nil || sp.Revoked {
		http.Error(w, "spoke not authorized", http.StatusForbidden)
		return
	}
	cert, err := h.issuer.SignSpoke([]byte(csrPEM), spokeID, h.cfg.SpokeCertTTL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	h.log.Info("issued spoke certificate", "spoke", spokeID)
	writeJSON(w, protocol.CertResponse{SpokeID: spokeID, CertPEM: string(cert)})
}

func (h *Hub) handleConfig(w http.ResponseWriter, r *http.Request, spokeID string) {
	sp, err := h.store.GetSpoke(r.Context(), spokeID)
	if err != nil {
		http.Error(w, "unknown spoke", http.StatusForbidden)
		return
	}
	writeJSON(w, protocol.ConfigResponse{SpokeID: spokeID, CanarySeed: sp.CanarySeed, Pack: h.packEnv})
}

func (h *Hub) handleEvents(w http.ResponseWriter, r *http.Request, spokeID string) {
	var batch events.Batch
	if err := decode(r, &batch, 8<<20); err != nil {
		h.noteShipment(spokeID, 0, 0, err, true)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if len(batch.Events) == 0 { // heartbeat: the spoke is alive and its queue is empty
		h.noteShipment(spokeID, batch.QueueDepth, batch.HeldOnSpoke, nil, false)
		writeJSON(w, protocol.IngestResponse{})
		return
	}
	n, err := h.Ingest(r.Context(), spokeID, batch.Events)
	if err != nil {
		h.log.Error("ingest failed", "spoke", spokeID, "batch", batch.ID, "err", err)
		// A batch the store can never accept is rejected for good, so the
		// spoke sets it aside instead of retrying it ahead of every later one.
		status := http.StatusInternalServerError
		if isDataError(err) {
			status = http.StatusUnprocessableEntity
		}
		h.noteShipment(spokeID, batch.QueueDepth, batch.HeldOnSpoke, err, status != http.StatusInternalServerError)
		http.Error(w, "ingest failed", status)
		return
	}
	h.noteShipment(spokeID, batch.QueueDepth, batch.HeldOnSpoke, nil, false)
	writeJSON(w, protocol.IngestResponse{Accepted: n})
}

// Ingest stores events from spokeID and updates incidents. Re-sent events are
// ignored, so a spoke may safely retry a batch.
func (h *Hub) Ingest(ctx context.Context, spokeID string, evs []events.Event) (int, error) {
	now := time.Now()
	for i := range evs {
		sanitizeEvent(&evs[i])
	}
	// Recording chunks go to their own table, not the event stream.
	var chunks []ReplayChunk
	evs = slices.DeleteFunc(evs, func(ev events.Event) bool {
		if ev.Kind != events.KindReplay {
			return false
		}
		viewID, _ := ev.Detail["view_id"].(string)
		data, _ := ev.Detail["rrweb"].(string)
		seq := 0
		switch v := ev.Detail["seq"].(type) {
		case float64:
			seq = int(v)
		case int:
			seq = v
		}
		if viewID != "" && json.Valid([]byte(data)) && len(data) <= 64<<10 {
			t := ev.Time
			if t.IsZero() || t.After(now.Add(5*time.Minute)) {
				t = now
			}
			chunks = append(chunks, ReplayChunk{ViewID: viewID, Seq: seq, SpokeID: spokeID, Source: ev.Source,
				Surface: ev.Surface, Time: t, Data: json.RawMessage(cleanJSON([]byte(data)))})
		}
		return true
	})
	if len(chunks) > 0 {
		if err := h.store.SaveReplayChunks(ctx, chunks); err != nil {
			return 0, err
		}
	}
	exposures := map[string]events.Event{} // exposure_id -> exposure, within this batch
	for i := range evs {
		ev := &evs[i]
		ev.SpokeID = spokeID // never trust the spoke's claim
		if len(ev.ID) != 32 {
			ev.ID = events.NewID()
		}
		if ev.Time.IsZero() || ev.Time.After(now.Add(5*time.Minute)) {
			ev.Time = now
		}
		ev.UserAgent = truncate(ev.UserAgent, 512)
		ev.Path = truncate(ev.Path, 2048)
		ev.Host = truncate(ev.Host, 255)
		if ev.Kind == events.KindCanaryExposed {
			if id, _ := ev.Detail["exposure_id"].(string); id != "" {
				exposures[id] = *ev
			}
		}
		if err := h.resolveCredential(ctx, ev); err != nil {
			return 0, err
		}
	}
	for i := range evs {
		if err := h.linkExposure(ctx, &evs[i], exposures); err != nil {
			return 0, err
		}
	}
	fresh, err := h.store.InsertEvents(ctx, evs)
	if err != nil {
		return 0, err
	}
	for _, ev := range fresh {
		h.enqueueEnrichment(ev.Source)
	}
	// Correlate the whole batch, not only the rows just inserted: if this
	// fails part way, the spoke resends the batch, the resend inserts
	// nothing, and the events must still reach their incident. Applying an
	// event twice leaves an incident unchanged.
	for _, ev := range evs {
		if err := h.correlate(ctx, ev); err != nil {
			return len(fresh), err
		}
	}
	return len(fresh), nil
}

// resolveCredential turns a presented credential into a canary use when it is
// a known fixed canary (by hash) or another spoke's minted canary (by MAC).
func (h *Hub) resolveCredential(ctx context.Context, ev *events.Event) error {
	if ev.Detail == nil {
		ev.Detail = map[string]any{}
	}
	if presented, _ := ev.Detail["presented_canary"].(string); presented != "" {
		delete(ev.Detail, "presented_canary")
		origin, slot, id, ok, err := h.verifyMinted(ctx, presented)
		if err != nil {
			return err
		}
		if ok {
			ev.Kind = events.KindCanaryUsed
			ev.CanarySlot = slot
			ev.Detail["canary_origin"] = origin
			ev.Detail["exposure_id"] = id
			return nil
		}
	}
	if ev.CredentialSHA256 == "" {
		return nil
	}
	origin, slot, err := h.store.LookupCanary(ctx, ev.CredentialSHA256)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	ev.CanarySlot = slot
	if ev.Kind == events.KindAuth {
		ev.Kind = events.KindCanaryUsed
	}
	ev.Detail["canary_origin"] = origin
	return nil
}

// verifyMinted checks a value against every spoke's seed.
func (h *Hub) verifyMinted(ctx context.Context, value string) (origin, slot, exposureID string, ok bool, err error) {
	seeds, err := h.spokeSeeds(ctx)
	if err != nil {
		return "", "", "", false, err
	}
	for id, seed := range seeds {
		for _, spec := range h.pack.Canaries {
			if exp, ok := canary.VerifyMinted(seed, spec, value); ok {
				return id, spec.Slot, exp, true, nil
			}
		}
	}
	return "", "", "", false, nil
}

// spokeSeeds returns every spoke's canary seed, cached briefly.
func (h *Hub) spokeSeeds(ctx context.Context) (map[string][]byte, error) {
	h.seedMu.Lock()
	defer h.seedMu.Unlock()
	if h.seeds != nil && time.Since(h.seedsAt) < time.Minute {
		return h.seeds, nil
	}
	spokes, err := h.store.ListSpokes(ctx)
	if err != nil {
		return nil, err
	}
	seeds := map[string][]byte{}
	for _, sp := range spokes {
		full, err := h.store.GetSpoke(ctx, sp.ID)
		if err != nil {
			return nil, err
		}
		seeds[sp.ID] = full.CanarySeed
	}
	h.seeds, h.seedsAt = seeds, time.Now()
	return seeds, nil
}

// linkExposure records which exposure a per-exposure canary use came from,
// so a use can be tied to the exact page view or reveal, even across IPs.
func (h *Hub) linkExposure(ctx context.Context, ev *events.Event, batch map[string]events.Event) error {
	if ev.Kind != events.KindCanaryUsed {
		return nil
	}
	id, _ := ev.Detail["exposure_id"].(string)
	if id == "" {
		return nil
	}
	exp, ok := batch[id]
	if !ok {
		var err error
		exp, err = h.store.FindExposure(ctx, id)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
	}
	ev.Detail["exposed_to"] = exp.Source
	ev.Detail["exposed_at"] = exp.Time
	ev.Detail["exposed_on"] = exp.Surface
	if m, _ := exp.Detail["module"].(string); m != "" {
		ev.Detail["exposed_by"] = m
	}
	return nil
}

func (h *Hub) correlate(ctx context.Context, ev events.Event) error {
	step, ok := correlate.Match(h.pack.Chain, ev)
	if !ok {
		return nil
	}
	if _, op := h.operatorFor(ev.Source); op {
		return nil // our own testing never opens incidents
	}
	if ev.FromModule() {
		return nil // keys from planted files are scanner harvest, not chain progress
	}
	h.corrMu.Lock()
	defer h.corrMu.Unlock()
	inc, err := h.store.IncidentBySource(ctx, ev.Source)
	if err != nil {
		return err
	}
	if inc == nil {
		inc = &correlate.Incident{}
	}
	origin := ev.SpokeID
	if o, ok := ev.Detail["canary_origin"].(string); ok && o != "" {
		origin = o
	}
	exposed := true
	if ev.Kind == events.KindCanaryUsed {
		// A linked exposure means we know where the key came from: either this
		// source, or another address (flagged as relayed by correlate.Apply).
		if to, _ := ev.Detail["exposed_to"].(string); to != "" {
			exposed = true
		} else if exposed, err = h.store.WasExposed(ctx, ev.Source, origin, ev.CanarySlot); err != nil {
			return err
		}
	}
	before := inc.Severity
	correlate.Apply(inc, h.pack.Chain, step, ev, origin, exposed)
	if err := h.store.SaveIncident(ctx, inc); err != nil {
		return err
	}
	if inc.Severity != before {
		h.log.Warn("incident", "id", inc.ID, "source", inc.Source, "severity", inc.Severity,
			"stages", inc.Stages, "score", inc.Score, "cross_spoke", inc.CrossSpoke, "out_of_band", inc.OutOfBand,
			"relayed", inc.Relayed)
	}
	return nil
}

// CreateSpoke registers a spoke, indexes its canaries and returns an
// enrollment bundle.
func (h *Hub) CreateSpoke(ctx context.Context, id string) (protocol.Bundle, error) {
	if !pki.ValidSpokeID(id) {
		return protocol.Bundle{}, fmt.Errorf("invalid spoke id %q", id)
	}
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return protocol.Bundle{}, err
	}
	if err := h.store.CreateSpoke(ctx, id, seed); err != nil {
		return protocol.Bundle{}, err
	}
	h.seedMu.Lock()
	h.seeds = nil // pick up the new spoke's seed on the next verification
	h.seedMu.Unlock()
	hashes := map[string]string{}
	for slot, v := range canary.NewSet(seed, h.pack).Slots() {
		hashes[canary.Hash(v)] = slot
	}
	if err := h.store.AddCanaries(ctx, id, hashes); err != nil {
		return protocol.Bundle{}, err
	}
	return h.NewEnrollment(ctx, id)
}

// NewEnrollment issues a fresh single-use token for an existing spoke.
func (h *Hub) NewEnrollment(ctx context.Context, id string) (protocol.Bundle, error) {
	sp, err := h.store.GetSpoke(ctx, id)
	if err != nil {
		return protocol.Bundle{}, err
	}
	if sp.Revoked {
		return protocol.Bundle{}, errors.New("spoke is revoked")
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return protocol.Bundle{}, err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	if err := h.store.CreateEnrollToken(ctx, hashToken(token), id, time.Now().Add(h.cfg.EnrollTTL)); err != nil {
		return protocol.Bundle{}, err
	}
	return protocol.Bundle{
		SpokeID:       id,
		HubURL:        h.cfg.HubURL,
		Token:         token,
		CAPEM:         string(h.issuer.RootPEM),
		PackPublicKey: []byte(h.issuer.PackKey.Public().(ed25519.PublicKey)),
	}, nil
}

// AdminHandler serves the admin API. It must only be bound to loopback or a
// private interface.
func (h *Hub) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /admin/spokes", func(w http.ResponseWriter, r *http.Request) {
		spokes, err := h.store.ListSpokes(r.Context())
		respond(w, spokes, err)
	})
	mux.HandleFunc("POST /admin/spokes", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID string `json:"id"`
		}
		if err := decode(r, &req, 4<<10); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		b, err := h.CreateSpoke(r.Context(), req.ID)
		respond(w, b, err)
	})
	mux.HandleFunc("POST /admin/spokes/{id}/enrollment", func(w http.ResponseWriter, r *http.Request) {
		b, err := h.NewEnrollment(r.Context(), r.PathValue("id"))
		respond(w, b, err)
	})
	mux.HandleFunc("POST /admin/spokes/{id}/revoke", func(w http.ResponseWriter, r *http.Request) {
		err := h.store.RevokeSpoke(r.Context(), r.PathValue("id"))
		respond(w, map[string]bool{"revoked": err == nil}, err)
	})
	mux.HandleFunc("GET /admin/incidents", func(w http.ResponseWriter, r *http.Request) {
		incs, err := h.store.ListIncidents(r.Context(), atoi(r.URL.Query().Get("limit")))
		respond(w, incs, err)
	})
	mux.HandleFunc("GET /admin/events", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		f := EventFilter{Source: q.Get("source"), Kind: q.Get("kind"), Surface: q.Get("surface"), Limit: atoi(q.Get("limit"))}
		if hours := atoi(q.Get("hours")); hours > 0 {
			f.Since = time.Now().Add(-time.Duration(min(hours, 24*90)) * time.Hour)
		}
		// An explicit ?from=/&to= range (Unix seconds or RFC3339) drills into a
		// brushed window on the timeline; it overrides ?hours=.
		if t := parseTime(q.Get("from")); !t.IsZero() {
			f.Since = t
		}
		if t := parseTime(q.Get("to")); !t.IsZero() {
			f.Until = t
		}
		evs, err := h.store.ListEvents(r.Context(), f)
		respond(w, evs, err)
	})
	mux.HandleFunc("GET /admin/health", func(w http.ResponseWriter, r *http.Request) {
		hr, err := h.HealthReport(r.Context())
		respond(w, hr, err)
	})
	mux.HandleFunc("GET /admin/overview", func(w http.ResponseWriter, r *http.Request) {
		hours := atoi(r.URL.Query().Get("hours"))
		if hours <= 0 || hours > 24*90 {
			hours = 24
		}
		o, err := h.store.Overview(r.Context(), time.Now().Add(-time.Duration(hours)*time.Hour), h.pack.Chain, h.operatorPrefixes())
		respond(w, o, err)
	})
	mux.HandleFunc("GET /admin/actors", func(w http.ResponseWriter, r *http.Request) {
		actors, sessions, err := h.Analyze(r.Context(), windowFrom(r))
		respond(w, map[string]any{"summary": classify.Summary(actors), "actors": actors, "sessions": sessions}, err)
	})
	mux.HandleFunc("GET /admin/research", func(w http.ResponseWriter, r *http.Request) {
		res, err := h.Research(r.Context(), windowFrom(r))
		respond(w, res, err)
	})
	mux.HandleFunc("GET /admin/attack-map", func(w http.ResponseWriter, r *http.Request) {
		since, until := windowRange(r)
		m, err := h.AttackMap(r.Context(), since, until, classSet(r.URL.Query().Get("classes")))
		respond(w, m, err)
	})
	mux.HandleFunc("GET /admin/attack-map/replay", func(w http.ResponseWriter, r *http.Request) {
		since, until := windowRange(r)
		m, err := h.AttackReplay(r.Context(), since, until, classSet(r.URL.Query().Get("classes")))
		respond(w, m, err)
	})
	mux.HandleFunc("GET /admin/actors/{source}", func(w http.ResponseWriter, r *http.Request) {
		evs, err := h.store.ListEvents(r.Context(), EventFilter{Source: r.PathValue("source"), Limit: 1000})
		if err != nil {
			respond(w, nil, err)
			return
		}
		a := classify.Classify(r.PathValue("source"), evs)
		h.locate(&a)
		respond(w, a, nil)
	})
	// The fixed value of a canary slot, for planting it in published
	// material such as the example repository.
	mux.HandleFunc("GET /admin/spokes/{id}/canaries/{slot}", func(w http.ResponseWriter, r *http.Request) {
		sp, err := h.store.GetSpoke(r.Context(), r.PathValue("id"))
		if err != nil {
			respond(w, nil, err)
			return
		}
		v := canary.NewSet(sp.CanarySeed, h.pack).Value(r.PathValue("slot"))
		if v == "" {
			respond(w, nil, ErrNotFound)
			return
		}
		respond(w, map[string]string{"spoke": sp.ID, "slot": r.PathValue("slot"), "value": v}, nil)
	})
	// Exports for analytics and threat-intelligence sharing; operator traffic
	// is always excluded.
	mux.HandleFunc("GET /admin/export/{name}", func(w http.ResponseWriter, r *http.Request) {
		since := windowFrom(r)
		now := time.Now()
		name := r.PathValue("name")
		if name == "events.jsonl" {
			evs, err := h.store.EventsSince(r.Context(), since, maxClassifyEvents)
			if err != nil {
				respond(w, nil, err)
				return
			}
			evs = slices.DeleteFunc(evs, func(ev events.Event) bool { _, op := h.operatorFor(ev.Source); return op })
			w.Header().Set("Content-Type", "application/x-ndjson")
			_ = export.JSONL(w, evs)
			return
		}
		an, err := h.analyze(r.Context(), since)
		if err != nil {
			respond(w, nil, err)
			return
		}
		actors, sessions := an.actors, an.sessions
		actors = slices.DeleteFunc(actors, func(a classify.Actor) bool { return a.Class == classify.Operator })
		sessions = slices.DeleteFunc(sessions, func(s classify.Session) bool { return s.Class == classify.Operator })
		switch name {
		case "actors.jsonl":
			w.Header().Set("Content-Type", "application/x-ndjson")
			_ = export.JSONL(w, actors)
		case "sessions.jsonl":
			w.Header().Set("Content-Type", "application/x-ndjson")
			_ = export.JSONL(w, sessions)
		case "campaigns.jsonl":
			w.Header().Set("Content-Type", "application/x-ndjson")
			_ = export.JSONL(w, an.campaigns)
		case "iocs.stix.json":
			w.Header().Set("Content-Type", "application/stix+json;version=2.1")
			_ = export.STIX(w, h.cfg.Producer, actors, now)
		case "dnsbl.zone":
			w.Header().Set("Content-Type", "text/plain")
			_ = export.DNSBL(w, h.cfg.DNSBLZone, actors, now)
		case "blocklist.csv":
			w.Header().Set("Content-Type", "text/csv")
			_ = export.CSV(w, actors)
		default:
			http.Error(w, "unknown export", http.StatusNotFound)
		}
	})
	mux.HandleFunc("GET /admin/replays", func(w http.ResponseWriter, r *http.Request) {
		list, err := h.store.ListReplays(r.Context(), r.URL.Query().Get("source"), atoi(r.URL.Query().Get("limit")))
		respond(w, list, err)
	})
	mux.HandleFunc("GET /admin/replays/{view}", func(w http.ResponseWriter, r *http.Request) {
		evs, err := h.store.GetReplay(r.Context(), r.PathValue("view"))
		if err == nil && len(evs) == 0 {
			err = ErrNotFound
		}
		respond(w, evs, err)
	})
	mux.HandleFunc("GET /admin/operators", func(w http.ResponseWriter, r *http.Request) {
		ops, err := h.store.ListOperators(r.Context())
		respond(w, ops, err)
	})
	mux.HandleFunc("POST /admin/operators", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			CIDR string `json:"cidr"`
			Note string `json:"note"`
		}
		if err := decode(r, &req, 4<<10); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		p, err := ParsePrefix(req.CIDR)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := h.store.AddOperator(r.Context(), Operator{CIDR: p.String(), Note: truncate(req.Note, 200)}); err != nil {
			respond(w, nil, err)
			return
		}
		removed, err := h.store.DeleteIncidentsIn(r.Context(), p)
		if err == nil {
			err = h.reloadOperators(r.Context())
		}
		respond(w, map[string]any{"cidr": p.String(), "incidents_removed": removed}, err)
	})
	mux.HandleFunc("DELETE /admin/operators/{cidr...}", func(w http.ResponseWriter, r *http.Request) {
		err := h.store.RemoveOperator(r.Context(), r.PathValue("cidr"))
		if err == nil {
			err = h.reloadOperators(r.Context())
		}
		respond(w, map[string]bool{"removed": err == nil}, err)
	})
	mux.HandleFunc("GET /admin/persona", func(w http.ResponseWriter, r *http.Request) {
		respond(w, map[string]any{"id": h.pack.ID, "version": h.pack.Version, "company": h.pack.Company.Name,
			"domain": h.pack.Company.Domain, "chain": h.pack.Chain}, nil)
	})

	root := http.NewServeMux()
	root.Handle("/admin/", h.requireAdmin(noStore(mux)))
	root.Handle("/", dashboard.Handler())
	return root
}

// maxClassifyEvents bounds the work of one classification pass.
const maxClassifyEvents = 300_000

// Actors classifies every source active since the given time, most
// interesting first: rogue agents, then AI agents, then the rest; within a
// class by agent-likeness score and activity.
func (h *Hub) Actors(ctx context.Context, since time.Time) ([]classify.Actor, error) {
	actors, _, err := h.Analyze(ctx, since)
	return actors, err
}

// Analyze classifies every source active since the given time, groups
// addresses that are one client into sessions, and assigns behavioral
// clusters and campaigns.
func (h *Hub) Analyze(ctx context.Context, since time.Time) ([]classify.Actor, []classify.Session, error) {
	a, err := h.analyze(ctx, since)
	return a.actors, a.sessions, err
}

func (h *Hub) analyze(ctx context.Context, since time.Time) (analysis, error) {
	evs, err := h.store.EventsSince(ctx, since, maxClassifyEvents)
	if err != nil {
		return analysis{}, err
	}
	var actors []classify.Actor
	bySource := map[string][]events.Event{}
	for i := 0; i < len(evs); {
		j := i
		for j < len(evs) && evs[j].Source == evs[i].Source {
			j++
		}
		bySource[evs[i].Source] = evs[i:j]
		actors = append(actors, classify.Classify(evs[i].Source, evs[i:j]))
		i = j
	}
	// A key revealed to one address and used from another ties both
	// addresses to one actor: the reader is as much a rogue agent as the user.
	relayedFrom := map[string][]string{} // exposing source -> using sources
	for _, ev := range evs {
		if to, _ := ev.Detail["exposed_to"].(string); ev.Kind == events.KindCanaryUsed && to != "" && to != ev.Source {
			if !slices.Contains(relayedFrom[to], ev.Source) {
				relayedFrom[to] = append(relayedFrom[to], ev.Source)
			}
		}
	}
	for i := range actors {
		if users := relayedFrom[actors[i].Source]; len(users) > 0 {
			classify.MarkRelaySource(&actors[i], users)
		}
	}
	sources := make([]string, len(actors))
	for i, a := range actors {
		sources[i] = a.Source
	}
	stored, err := h.store.RDNSFor(ctx, sources)
	if err != nil {
		return analysis{}, err
	}
	for i := range actors {
		r, ok := stored[actors[i].Source]
		if !ok {
			h.enqueueEnrichment(actors[i].Source)
			continue
		}
		host := ""
		if len(r.Confirmed) > 0 {
			host = r.Confirmed[0]
		} else if len(r.Hostnames) > 0 {
			host = r.Hostnames[0]
		}
		actors[i].Hostname, actors[i].Network = host, rdns.Network(host)
	}
	h.checkCrawlers(ctx, actors, stored)
	for i := range actors {
		h.locate(&actors[i])
	}
	for i := range actors {
		if p, ok := h.operatorFor(actors[i].Source); ok {
			classify.MarkOperator(&actors[i], p.String())
		}
	}
	sessions := classify.GroupSessions(actors, bySource)
	h.linkMu.RLock()
	for i := range actors {
		classify.ApplyLinks(&actors[i], h.links[actors[i].Source])
	}
	h.linkMu.RUnlock()

	rank := map[string]int{}
	for i, c := range classify.Order {
		rank[c] = i
	}
	slices.SortStableFunc(actors, func(a, b classify.Actor) int {
		return cmp.Or(rank[a.Class]-rank[b.Class], b.Score-a.Score,
			b.Features.Requests-a.Features.Requests, strings.Compare(a.Source, b.Source))
	})
	a := analysis{actors: actors, sessions: sessions, bySource: bySource}
	correlateResearch(&a)
	return a, nil
}

// IndexCanaries (re)indexes every spoke's fixed canary values, so slots added
// to the world pack after a spoke enrolled are recognised too.
func (h *Hub) IndexCanaries(ctx context.Context) error {
	spokes, err := h.store.ListSpokes(ctx)
	if err != nil {
		return err
	}
	for _, sp := range spokes {
		full, err := h.store.GetSpoke(ctx, sp.ID)
		if err != nil {
			return err
		}
		hashes := map[string]string{}
		for slot, v := range canary.NewSet(full.CanarySeed, h.pack).Slots() {
			hashes[canary.Hash(v)] = slot
		}
		if err := h.store.AddCanaries(ctx, sp.ID, hashes); err != nil {
			return err
		}
	}
	return nil
}

// ParsePrefix accepts a CIDR or a bare IP address.
func ParsePrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("not an IP address or CIDR: %q", s)
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// LoadOperators seeds operator ranges from the configuration and loads the
// stored list. Call once at startup.
func (h *Hub) LoadOperators(ctx context.Context) error {
	for _, c := range h.cfg.Operators {
		p, err := ParsePrefix(c)
		if err != nil {
			return err
		}
		if err := h.store.AddOperator(ctx, Operator{CIDR: p.String(), Note: "from environment"}); err != nil {
			return err
		}
		if _, err := h.store.DeleteIncidentsIn(ctx, p); err != nil {
			return err
		}
	}
	return h.reloadOperators(ctx)
}

func (h *Hub) reloadOperators(ctx context.Context) error {
	ops, err := h.store.ListOperators(ctx)
	if err != nil {
		return err
	}
	var ps []netip.Prefix
	for _, o := range ops {
		if p, err := ParsePrefix(o.CIDR); err == nil {
			ps = append(ps, p)
		}
	}
	h.opMu.Lock()
	h.operators = ps
	h.opMu.Unlock()
	return nil
}

func (h *Hub) operatorPrefixes() []netip.Prefix {
	h.opMu.RLock()
	defer h.opMu.RUnlock()
	return slices.Clone(h.operators)
}

// operatorFor returns the operator range containing source, if any.
func (h *Hub) operatorFor(source string) (netip.Prefix, bool) {
	for _, p := range h.operatorPrefixes() {
		if InPrefixes(source, []netip.Prefix{p}) {
			return p, true
		}
	}
	return netip.Prefix{}, false
}

// RunEnrichment looks up reverse DNS for each new source once, in the
// background, and stores the result. It needs the resolver service.
func (h *Hub) RunEnrichment(ctx context.Context) {
	if h.cfg.ResolverURL == "" {
		return
	}
	const workers = 8
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.enrichWorker(ctx)
		}()
	}
	wg.Wait()
}

func (h *Hub) enrichWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case src := <-h.enrichQ:
			res, err := h.lookupRDNS(ctx, src)
			rec := SourceRDNS{Source: src, Hostnames: res.Hostnames, Confirmed: res.Confirmed}
			if err != nil {
				rec.Error = truncate(err.Error(), 200)
			}
			if err := h.store.SaveRDNS(ctx, rec); err != nil {
				h.log.Warn("saving reverse DNS failed", "source", src, "err", err)
			}
		}
	}
}

// enqueueEnrichment schedules a reverse-DNS lookup for a new address.
func (h *Hub) enqueueEnrichment(source string) {
	if h.cfg.ResolverURL == "" {
		return
	}
	if _, err := netip.ParseAddr(source); err != nil {
		return
	}
	if _, loaded := h.enrichSeen.LoadOrStore(source, struct{}{}); loaded {
		return
	}
	select {
	case h.enrichQ <- source:
	default:
		h.enrichSeen.Delete(source) // queue full; try again on its next event
	}
}

// checkCrawlers verifies self-declared crawlers by reverse DNS through the
// resolver service. Without a resolver, or on errors, actors are unchanged.
func (h *Hub) checkCrawlers(ctx context.Context, actors []classify.Actor, stored map[string]SourceRDNS) {
	if h.cfg.ResolverURL == "" {
		return
	}
	type job struct {
		i         int
		family    rdns.Family
		stored    rdns.Result
		hasStored bool
	}
	var jobs []job
	for i, a := range actors {
		if len(a.UserAgents) == 0 {
			continue
		}
		// Pseudonymized sources are not addresses and cannot be verified.
		if _, err := netip.ParseAddr(a.Source); err != nil {
			continue
		}
		if f, ok := rdns.Claimed(a.UserAgents[0]); ok {
			j := job{i: i, family: f}
			if r, ok := stored[a.Source]; ok && r.Error == "" {
				j.stored, j.hasStored = rdns.Result{IP: a.Source, Hostnames: r.Hostnames, Confirmed: r.Confirmed}, true
			}
			jobs = append(jobs, j)
		}
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for _, j := range jobs {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			res, ok := j.stored, j.hasStored
			if !ok {
				var err error
				if res, err = h.lookupRDNS(ctx, actors[j.i].Source); err != nil {
					return
				}
			}
			host, ok := rdns.Verified(res, j.family)
			classify.ApplyCrawlerCheck(&actors[j.i], j.family.Name, ok, host)
		}()
	}
	wg.Wait()
}

func (h *Hub) lookupRDNS(ctx context.Context, ip string) (rdns.Result, error) {
	h.rdnsMu.Lock()
	if e, ok := h.rdnsCache[ip]; ok && time.Since(e.at) < 24*time.Hour {
		h.rdnsMu.Unlock()
		return e.res, nil
	}
	h.rdnsMu.Unlock()

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.cfg.ResolverURL+"/v1/verify?ip="+url.QueryEscape(ip), nil)
	if err != nil {
		return rdns.Result{}, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return rdns.Result{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return rdns.Result{}, fmt.Errorf("resolver: %s", resp.Status)
	}
	var res rdns.Result
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&res); err != nil {
		return rdns.Result{}, err
	}
	h.rdnsMu.Lock()
	if h.rdnsCache == nil {
		h.rdnsCache = map[string]rdnsEntry{}
	}
	h.rdnsCache[ip] = rdnsEntry{res, time.Now()}
	h.rdnsMu.Unlock()
	return res, nil
}

// windowFrom reads ?hours= (default 24, max 90 days).
func windowFrom(r *http.Request) time.Time {
	hours := atoi(r.URL.Query().Get("hours"))
	if hours <= 0 || hours > 24*90 {
		hours = 24
	}
	return time.Now().Add(-time.Duration(hours) * time.Hour)
}

// windowRange reads an explicit ?from=/&to= range (Unix seconds or an RFC3339 /
// datetime-local string), falling back to ?hours= for the start and now for the
// end. The start is clamped to at most 90 days before the end.
func windowRange(r *http.Request) (since, until time.Time) {
	now := time.Now()
	until = now
	if t := parseTime(r.URL.Query().Get("to")); !t.IsZero() {
		until = t
	}
	if t := parseTime(r.URL.Query().Get("from")); !t.IsZero() {
		since = t
	} else {
		since = windowFrom(r)
	}
	if since.After(until) || until.Sub(since) > 90*24*time.Hour {
		since = until.Add(-24 * time.Hour)
	}
	return since, until
}

// parseTime accepts Unix seconds, RFC3339, or a bare datetime-local value.
func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return time.Unix(n, 0)
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// classSet parses a comma-separated actor-class filter into a set.
func classSet(s string) map[string]bool {
	if s == "" {
		return nil
	}
	set := map[string]bool{}
	for _, c := range strings.Split(s, ",") {
		if c = strings.TrimSpace(c); c != "" {
			set[c] = true
		}
	}
	return set
}

func noStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func (h *Hub) requireAdmin(next http.Handler) http.Handler {
	want := []byte("Bearer " + h.cfg.AdminToken)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), want) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func hashToken(t string) string {
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}

func decode(r *http.Request, v any, limit int64) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, limit))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func respond(w http.ResponseWriter, v any, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		http.Error(w, "not found", http.StatusNotFound)
	case err != nil:
		http.Error(w, err.Error(), http.StatusBadRequest)
	default:
		writeJSON(w, v)
	}
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "")
}
