// Typed client for the hub admin API. The token lives in sessionStorage only,
// so it is dropped when the tab closes.
import { lastLoaded } from './state'

export interface Totals {
  events: number
  requests: number
  sources: number
  tls_hellos: number
  fingerprints: number
  canary_uses: number
}
export interface FunnelStage { stage: number; name: string; sources: number }
export interface TimeBucket { time: string; requests: number; sources: number }
export interface SourceStat { source: string; events: number; last_seen: string; user_agent: string }
export interface Fingerprint { ja4: string; sources: number; requests: number; user_agent: string }
export interface UserAgentStat { user_agent: string; requests: number; sources: number }
export interface PathStat { surface: string; path: string; requests: number; sources: number }
export interface ExploitStat {
  module: string
  attack: string
  cves: string[] | null
  attempts: number
  probes: number
  sources: number
  last_seen: string
}
export interface Overview {
  since: string
  totals: Totals
  severity: Record<string, number>
  funnel: FunnelStage[] | null
  timeline: TimeBucket[] | null
  top_sources: SourceStat[] | null
  top_fingerprints: Fingerprint[] | null
  top_user_agents: UserAgentStat[] | null
  top_paths: PathStat[] | null
  exploits: ExploitStat[] | null
}
export interface Incident {
  id: number
  source: string
  spokes: string[]
  first_seen: string
  last_seen: string
  stages: number[]
  score: number
  severity: 'critical' | 'high' | 'medium' | 'low'
  cross_spoke: boolean
  out_of_band: boolean
  relayed: boolean
}
export interface EventRecord {
  id: string
  spoke_id?: string
  time: string
  protocol: string
  surface: string
  kind: string
  source: string
  user_agent?: string
  method?: string
  host?: string
  path?: string
  status?: number
  canary_slot?: string
  credential_sha256?: string
  detail?: Record<string, unknown>
}
export interface Spoke { id: string; created_at: string; revoked: boolean; last_seen?: string }
export interface SpokeIngest {
  spoke_id: string
  status: 'ok' | 'failing' | 'backlog' | 'silent' | 'rejected'
  last_contact?: string
  last_ok?: string
  failing_since?: string
  last_error?: string
  failures: number
  queue_depth: number
  rejected_24h: number
}
export interface IngestHealth { ok: boolean; problems: string[]; spokes: SpokeIngest[]; checked_at: string }
export interface ChainStep { stage: number; name: string; kind: string; slot: string; score: number }
export interface Persona { id: string; version: string; company: string; domain: string; chain: ChainStep[] }

export type ActorClass = 'rogue_agent' | 'ai_agent' | 'scanner' | 'crawler' | 'browser' | 'unknown' | 'operator'
export interface ActorFeatures {
  requests: number
  distinct_paths: number
  surfaces: number
  wordlist_hits: number
  not_found: number
  head_or_options: number
  posts: number
  read_agent_docs: boolean
  fetched_robots: boolean
  max_stage: number
  canary_uses: number
  used_after_seeing: boolean
  used_unseen: boolean
  mcp_initialize: boolean
  mcp_tools_list: boolean
  mcp_tool_calls: number
  llm_calls: number
  sdk_headers: boolean
  auth_attempts: number
  login_attempts: number
  median_gap_ms: number
  html_pages: number
  wordlist_ratio: number
  declared_as: string
  ssh_connects?: number
  ssh_logins?: number
  ssh_auth_fails?: number
  ssh_usernames?: string[]
  ssh_commands?: string[]
  ssh_client?: string
  ssh_key_fingerprint?: string
  ssh_forward?: number
  ssh_exfil_url?: string
}
export interface Actor {
  source: string
  class: ActorClass
  confidence: 'high' | 'medium' | 'low'
  score: number
  capability: number
  depth: string
  reasons: string[]
  features: ActorFeatures
  first_seen: string
  last_seen: string
  user_agents: string[] | null
  ja4: string[] | null
  crawler_check?: string
  hostname?: string
  network?: string
  country_code?: string
  country?: string
  session_id?: string
  session_size?: number
  links?: ActorLink[]
  frameworks?: FrameworkLabel[]
  cluster_id?: string
  campaign_id?: string
}
export interface FrameworkLabel {
  name: string
  kind: string
  confidence: number
  level: 'likely' | 'possible'
  families: string[]
  evidence: string[]
}
export interface Cluster { id: string; members: string[]; classes: string[]; signature: string[]; cohesion: number }
export interface Campaign {
  id: string
  members: string[]
  sessions?: string[]
  clusters?: string[]
  classes: string[]
  first_seen: string
  last_seen: string
  max_stage: number
  severity: 'critical' | 'high' | 'medium' | 'low'
  score: number
  networks?: string[]
  identities?: string[]
  frameworks?: string[]
  joins: string[]
  summary: string
}
export interface LureStat { family: string; variant: string; text: string; shown: number; called: number; rate: number }
export interface Deception {
  lures: LureStat[] | null
  hints_shown: number
  hints_followed: number
  honey_scopes: Record<string, number>
  decoy_agent: number
  honey_tools: number
  depth: Record<string, number>
}
export interface Research { since: string; clusters: Cluster[] | null; campaigns: Campaign[] | null; deception: Deception }
// A path in the link graph from this source to a known agent.
export interface ActorLink {
  agent: string
  class: ActorClass
  seen?: string
  via: string[]
}
export interface Session {
  id: string
  members: string[]
  links: string[]
  class: ActorClass
  score: number
  reasons: string[]
  first_seen: string
  last_seen: string
  user_agent?: string
}
export interface ReplaySummary { view_id: string; source: string; surface: string; start: string; end: string; chunks: number; bytes: number }
export interface OperatorRange { cidr: string; note: string; created_at: string }
export interface Actors { summary: Record<ActorClass, number>; actors: Actor[] | null; sessions: Session[] | null }

const TOKEN_KEY = 'agenttrap.admin.token'

export interface MapPoint {
  lat: number
  lon: number
  city?: string
  country?: string
  country_code?: string
  count: number
  score: number
  top_class: string
  sources?: string[]
}
export interface AttackMap {
  enabled: boolean
  attribution: string
  generated?: string
  since?: string
  until?: string
  actors?: number
  mapped?: number
  points: MapPoint[] | null
  countries: MapPoint[] | null
}
export interface ReplayPlace { lat: number; lon: number; city?: string; country?: string; country_code?: string }
// One place's activity in one frame (short keys keep long ranges small).
export interface ReplayCell { f: number; p: number; a: number; e: number; n: number; s: number; c: string; src?: string[] }
export interface AttackReplay {
  enabled: boolean
  attribution: string
  since: string
  until: string
  step_seconds: number
  frames: number
  activity: number[]
  places: ReplayPlace[]
  cells: ReplayCell[]
  actors: number
  mapped: number
}
export interface AttackMapQuery {
  hours?: number | undefined
  from?: number | undefined
  to?: number | undefined
  classes?: string[] | undefined
}

export function getToken(): string {
  try {
    return sessionStorage.getItem(TOKEN_KEY) ?? ''
  } catch {
    return ''
  }
}

export function setToken(token: string): void {
  try {
    if (token) sessionStorage.setItem(TOKEN_KEY, token)
    else sessionStorage.removeItem(TOKEN_KEY)
  } catch {
    /* storage unavailable: token lives only in memory for this page */
  }
  memoryToken = token
}

let memoryToken = ''

export class UnauthorizedError extends Error {}

async function get<T>(path: string, params: Record<string, string | number | undefined> = {}): Promise<T> {
  const qs = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== '') qs.set(k, String(v))
  }
  const url = qs.size ? `${path}?${qs.toString()}` : path
  const res = await fetch(url, { headers: { Authorization: `Bearer ${getToken() || memoryToken}` } })
  if (res.status === 401) throw new UnauthorizedError('unauthorized')
  if (!res.ok) throw new Error(`${res.status} ${await res.text()}`)
  const out = (await res.json()) as T
  lastLoaded.value = Date.now()
  return out
}

async function send<T>(method: 'POST' | 'DELETE', path: string, body?: unknown): Promise<T> {
  const init: RequestInit = { method, headers: { Authorization: `Bearer ${getToken() || memoryToken}`, 'Content-Type': 'application/json' } }
  if (body !== undefined) init.body = JSON.stringify(body)
  const res = await fetch(path, init)
  if (res.status === 401) throw new UnauthorizedError('unauthorized')
  if (!res.ok) throw new Error(`${res.status} ${await res.text()}`)
  return (await res.json()) as T
}

export const api = {
  overview: (hours: number) => get<Overview>('/admin/overview', { hours }),
  health: () => get<IngestHealth>('/admin/health'),
  incidents: (limit = 500) => get<Incident[] | null>('/admin/incidents', { limit }),
  events: (f: { source?: string; kind?: string; surface?: string; hours?: number; limit?: number; from?: number | undefined; to?: number | undefined }) =>
    get<EventRecord[] | null>('/admin/events', f),
  spokes: () => get<Spoke[] | null>('/admin/spokes'),
  persona: () => get<Persona>('/admin/persona'),
  actors: (hours: number) => get<Actors>('/admin/actors', { hours }),
  research: (hours: number) => get<Research>('/admin/research', { hours }),
  attackMap: (q: AttackMapQuery) =>
    get<AttackMap>('/admin/attack-map', {
      hours: q.hours,
      from: q.from,
      to: q.to,
      classes: q.classes && q.classes.length ? q.classes.join(',') : undefined,
    }),
  attackReplay: (q: AttackMapQuery) =>
    get<AttackReplay>('/admin/attack-map/replay', {
      hours: q.hours,
      from: q.from,
      to: q.to,
      classes: q.classes && q.classes.length ? q.classes.join(',') : undefined,
    }),
  actor: (source: string) => get<Actor>(`/admin/actors/${encodeURIComponent(source)}`),
  operators: () => get<OperatorRange[] | null>('/admin/operators'),
  replays: (source: string) => get<ReplaySummary[] | null>('/admin/replays', { source, limit: 50 }),
  replay: (view: string) => get<unknown[]>(`/admin/replays/${encodeURIComponent(view)}`),
  addOperator: (cidr: string, note: string) => send<{ cidr: string; incidents_removed: number }>('POST', '/admin/operators', { cidr, note }),
  removeOperator: (cidr: string) => send<{ removed: boolean }>('DELETE', `/admin/operators/${cidr}`),
}
