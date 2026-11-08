package hub

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"time"

	"agenttrap/internal/correlate"
	"agenttrap/internal/events"
	"agenttrap/internal/worldpack"
)

// ErrNotFound is returned when a record does not exist.
var ErrNotFound = errors.New("not found")

// Spoke is a registered sensor node.
type Spoke struct {
	ID         string     `json:"id"`
	CreatedAt  time.Time  `json:"created_at"`
	Revoked    bool       `json:"revoked"`
	LastSeen   *time.Time `json:"last_seen,omitempty"`
	CanarySeed []byte     `json:"-"`
}

// EventFilter narrows ListEvents.
type EventFilter struct {
	Source  string
	Kind    string
	Surface string
	Since   time.Time
	Until   time.Time // zero = no upper bound
	Limit   int
}

// SourceBucket is one source's event count in one time bucket.
type SourceBucket struct {
	Source string
	Start  time.Time
	Events int
}

// Store is the hub's persistence layer. PostgreSQL is authoritative in
// production; MemStore exists for tests.
type Store interface {
	CreateSpoke(ctx context.Context, id string, seed []byte) error
	GetSpoke(ctx context.Context, id string) (Spoke, error)
	ListSpokes(ctx context.Context) ([]Spoke, error)
	RevokeSpoke(ctx context.Context, id string) error
	TouchSpoke(ctx context.Context, id string, at time.Time) error

	CreateEnrollToken(ctx context.Context, tokenHash, spokeID string, expires time.Time) error
	// ConsumeEnrollToken marks a token used and returns its spoke. It fails if
	// the token is unknown, expired or already used.
	ConsumeEnrollToken(ctx context.Context, tokenHash string, now time.Time) (string, error)

	// AddCanaries indexes canary hashes (hash -> slot) for a spoke.
	AddCanaries(ctx context.Context, spokeID string, hashes map[string]string) error
	LookupCanary(ctx context.Context, hash string) (spokeID, slot string, err error)

	// InsertEvents stores events, skipping IDs already stored, and returns
	// only the newly inserted ones.
	InsertEvents(ctx context.Context, evs []events.Event) ([]events.Event, error)
	ListEvents(ctx context.Context, f EventFilter) ([]events.Event, error)
	// WasExposed reports whether source was ever shown slot by originSpoke.
	WasExposed(ctx context.Context, source, originSpoke, slot string) (bool, error)

	IncidentBySource(ctx context.Context, source string) (*correlate.Incident, error)
	SaveIncident(ctx context.Context, inc *correlate.Incident) error
	ListIncidents(ctx context.Context, limit int) ([]correlate.Incident, error)

	// FindExposure returns the canary_exposed event carrying exposureID.
	FindExposure(ctx context.Context, exposureID string) (events.Event, error)

	// EventsSince returns events at or after since, grouped by source and in
	// time order, up to limit, for behavior classification.
	EventsSince(ctx context.Context, since time.Time, limit int) ([]events.Event, error)
	// EventsBetween returns events in [from, to), grouped by source and in
	// time order, up to limit.
	EventsBetween(ctx context.Context, from, to time.Time, limit int) ([]events.Event, error)
	// OldestEvent returns the time of the oldest stored event (zero if none).
	OldestEvent(ctx context.Context) (time.Time, error)
	// SourceActivity counts each source's events in [since, until) per
	// step-wide bucket aligned to since, for the attack-map replay.
	SourceActivity(ctx context.Context, since, until time.Time, step time.Duration) ([]SourceBucket, error)

	// Overview summarizes activity since the given time for the dashboard,
	// leaving out operator addresses.
	Overview(ctx context.Context, since time.Time, chain []worldpack.ChainStep, exclude []netip.Prefix) (Overview, error)

	ListOperators(ctx context.Context) ([]Operator, error)
	AddOperator(ctx context.Context, op Operator) error
	RemoveOperator(ctx context.Context, cidr string) error
	// DeleteIncidentsIn removes incidents whose source falls in prefix.
	DeleteIncidentsIn(ctx context.Context, prefix netip.Prefix) (int, error)

	SaveReplayChunks(ctx context.Context, chunks []ReplayChunk) error
	// ListReplays summarizes recorded page views, newest first; source may be empty.
	ListReplays(ctx context.Context, source string, limit int) ([]ReplaySummary, error)
	// GetReplay returns a page view's rrweb events in order.
	GetReplay(ctx context.Context, viewID string) ([]json.RawMessage, error)

	SaveRDNS(ctx context.Context, r SourceRDNS) error
	// RDNSFor returns stored reverse DNS for the given sources.
	RDNSFor(ctx context.Context, sources []string) (map[string]SourceRDNS, error)
}

// ReplayChunk is one rrweb recording chunk of a page view.
type ReplayChunk struct {
	ViewID  string
	Seq     int
	SpokeID string
	Source  string
	Surface string
	Time    time.Time
	Data    json.RawMessage // JSON array of rrweb events
}

// ReplaySummary describes one recorded page view.
type ReplaySummary struct {
	ViewID  string    `json:"view_id"`
	Source  string    `json:"source"`
	Surface string    `json:"surface"`
	Start   time.Time `json:"start"`
	End     time.Time `json:"end"`
	Chunks  int       `json:"chunks"`
	Bytes   int       `json:"bytes"`
}

// Operator is an address range whose traffic is ours (testing, monitoring).
type Operator struct {
	CIDR      string    `json:"cidr"`
	Note      string    `json:"note"`
	CreatedAt time.Time `json:"created_at"`
}

// SourceRDNS is the stored reverse-DNS result for one source address.
type SourceRDNS struct {
	Source    string    `json:"source"`
	Hostnames []string  `json:"hostnames"`
	Confirmed []string  `json:"confirmed"`
	CheckedAt time.Time `json:"checked_at"`
	Error     string    `json:"error,omitempty"`
}
