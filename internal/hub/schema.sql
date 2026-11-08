CREATE TABLE IF NOT EXISTS spokes (
    id          text PRIMARY KEY,
    created_at  timestamptz NOT NULL DEFAULT now(),
    revoked     boolean NOT NULL DEFAULT false,
    last_seen   timestamptz,
    canary_seed bytea NOT NULL
);

CREATE TABLE IF NOT EXISTS enroll_tokens (
    token_sha256 text PRIMARY KEY,
    spoke_id     text NOT NULL REFERENCES spokes(id),
    expires_at   timestamptz NOT NULL,
    used_at      timestamptz
);

CREATE TABLE IF NOT EXISTS canaries (
    value_sha256 text PRIMARY KEY,
    spoke_id     text NOT NULL REFERENCES spokes(id),
    slot         text NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id                text PRIMARY KEY,
    spoke_id          text NOT NULL REFERENCES spokes(id),
    ts                timestamptz NOT NULL,
    received_at       timestamptz NOT NULL DEFAULT now(),
    protocol          text NOT NULL,
    surface           text NOT NULL,
    kind              text NOT NULL,
    source            text NOT NULL,
    user_agent        text NOT NULL DEFAULT '',
    method            text NOT NULL DEFAULT '',
    host              text NOT NULL DEFAULT '',
    path              text NOT NULL DEFAULT '',
    status            integer NOT NULL DEFAULT 0,
    canary_slot       text NOT NULL DEFAULT '',
    credential_sha256 text NOT NULL DEFAULT '',
    detail            jsonb
);

CREATE INDEX IF NOT EXISTS events_ts_idx ON events (ts DESC);
CREATE INDEX IF NOT EXISTS events_source_idx ON events (source, ts DESC);
CREATE INDEX IF NOT EXISTS events_exposure_idx ON events (source, spoke_id, canary_slot) WHERE kind = 'canary_exposed';

CREATE TABLE IF NOT EXISTS incidents (
    id          bigserial PRIMARY KEY,
    source      text NOT NULL UNIQUE,
    spokes      text[] NOT NULL,
    first_seen  timestamptz NOT NULL,
    last_seen   timestamptz NOT NULL,
    stages      integer[] NOT NULL,
    score       integer NOT NULL,
    severity    text NOT NULL,
    cross_spoke boolean NOT NULL DEFAULT false,
    out_of_band boolean NOT NULL DEFAULT false
);

CREATE INDEX IF NOT EXISTS incidents_last_seen_idx ON incidents (last_seen DESC);

-- v0.6: per-exposure canaries
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS relayed boolean NOT NULL DEFAULT false;
CREATE INDEX IF NOT EXISTS events_exposure_id_idx ON events ((detail->>'exposure_id')) WHERE kind = 'canary_exposed';

-- v0.7: operator addresses (our own traffic) and reverse DNS per source
CREATE TABLE IF NOT EXISTS operators (
    cidr       text PRIMARY KEY,
    note       text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS source_rdns (
    source     text PRIMARY KEY,
    hostnames  text[] NOT NULL DEFAULT '{}',
    confirmed  text[] NOT NULL DEFAULT '{}',
    checked_at timestamptz NOT NULL DEFAULT now(),
    error      text NOT NULL DEFAULT ''
);

-- v0.8: rrweb session recordings, kept out of the events table
CREATE TABLE IF NOT EXISTS replay_chunks (
    view_id  text NOT NULL,
    seq      integer NOT NULL,
    spoke_id text NOT NULL,
    source   text NOT NULL,
    surface  text NOT NULL DEFAULT '',
    ts       timestamptz NOT NULL,
    data     jsonb NOT NULL,
    PRIMARY KEY (view_id, seq)
);
CREATE INDEX IF NOT EXISTS replay_chunks_source_idx ON replay_chunks (source, ts DESC);
