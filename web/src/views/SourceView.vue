<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { api, type Actor, type EventRecord, type Incident, type ReplaySummary, type Session } from '../api'
import { refreshTick } from '../state'
import { fmtTime } from '../format'
import { classMeta } from '../classes'
import Addr from '../components/Addr.vue'
import DepthMeter from '../components/DepthMeter.vue'
import EventTable from '../components/EventTable.vue'
import SeverityBadge from '../components/SeverityBadge.vue'
import ClassBadge from '../components/ClassBadge.vue'
import StepTimeline from '../components/StepTimeline.vue'

const props = defineProps<{ source: string }>()
const events = ref<EventRecord[]>([])
const incident = ref<Incident | null>(null)
const actor = ref<Actor | null>(null)
const session = ref<Session | null>(null)
const replays = ref<ReplaySummary[]>([])
const membership = ref<{ campaign: string | undefined; cluster: string | undefined }>({ campaign: undefined, cluster: undefined })
const error = ref('')
const notice = ref('')

async function markOperator(): Promise<void> {
  if (!window.confirm(`Treat ${props.source} as your own traffic? Its incidents will be removed.`)) return
  try {
    const res = await api.addOperator(props.source, 'marked from dashboard')
    notice.value = `Marked as operator; ${res.incidents_removed} incident(s) removed.`
    await load()
  } catch (e) {
    error.value = (e as Error).message
  }
}

async function load(): Promise<void> {
  try {
    const [evs, incs, act] = await Promise.all([
      api.events({ source: props.source, limit: 1000 }),
      api.incidents(1000),
      api.actor(props.source),
    ])
    actor.value = act
    replays.value = (await api.replays(props.source)) ?? []
    const all = await api.actors(24 * 30)
    session.value = (all.sessions ?? []).find((s) => s.members.includes(props.source)) ?? null
    const me = (all.actors ?? []).find((a) => a.source === props.source)
    membership.value = { campaign: me?.campaign_id, cluster: me?.cluster_id }
    events.value = evs ?? []
    incident.value = (incs ?? []).find((i) => i.source === props.source) ?? null
    error.value = ''
  } catch (e) {
    error.value = (e as Error).message
  }
}
watch([() => props.source, refreshTick], load, { immediate: true })

const allReasons = ref(false)
const meta = computed(() => classMeta(actor.value?.class ?? 'unknown'))

const summary = computed(() => {
  const uas = new Set<string>()
  const ja4s = new Set<string>()
  const surfaces = new Set<string>()
  for (const e of events.value) {
    if (e.user_agent) uas.add(e.user_agent)
    const j = e.detail?.['ja4']
    if (typeof j === 'string') ja4s.add(j)
    if (e.surface) surfaces.add(e.surface)
  }
  return { uas: [...uas], ja4s: [...ja4s], surfaces: [...surfaces] }
})

// Request bodies the source sent to the JSON APIs, oldest first.
const payloads = computed(() =>
  events.value
    .filter((e) => typeof e.detail?.['body'] === 'string')
    .map((e) => {
      const raw = e.detail?.['body'] as string
      let pretty = raw
      try {
        pretty = JSON.stringify(JSON.parse(raw), null, 2)
      } catch {
        /* not JSON: show as sent */
      }
      return { id: e.id, time: e.time, method: e.method ?? '', surface: e.surface, path: e.path ?? '', body: pretty,
        truncated: e.detail?.['body_truncated'] === true }
    })
    .reverse(),
)
</script>

<template>
  <nav class="crumbs small"><RouterLink to="/actors">Actors</RouterLink> <span class="muted">/</span> <span class="mono">{{ source }}</span></nav>
  <section class="card id-card" :style="{ '--cc': meta.color }">
    <div class="id-main">
      <div class="id-top">
        <ClassBadge v-if="actor" :cls="actor.class" :confidence="actor.confidence" />
        <span v-if="actor" class="pill">score {{ actor.score }}</span>
        <span v-if="incident" class="pill"><SeverityBadge :severity="incident.severity" /></span>
      </div>
      <h1 class="id-ip"><Addr :ip="source" :cc="actor?.country_code" :country="actor?.country" :link="false" /></h1>
      <p class="id-where muted">
        {{ [actor?.country, actor?.network, actor?.hostname].filter(Boolean).join(' · ') || 'Location unknown' }}<span v-if="actor?.crawler_check"> · crawler check: {{ actor.crawler_check }}</span>
      </p>
      <div class="id-chips">
        <span v-if="actor?.frameworks?.some((f) => f.level === 'likely')" class="pill">{{ actor.frameworks.filter((f) => f.level === 'likely').map((f) => f.name).join(', ') }}</span>
        <span v-else-if="summary.uas[0]" class="pill mono ua-pill" :title="summary.uas.join('\n')">{{ summary.uas[0] }}</span>
        <RouterLink v-if="session" class="pill" :to="{ path: '/actors' }">one of {{ session.members.length }} addresses</RouterLink>
        <RouterLink v-if="membership.campaign" class="pill" to="/research">campaign {{ membership.campaign }}</RouterLink>
        <span v-if="actor" class="pill">seen {{ fmtTime(actor.first_seen) }} → {{ fmtTime(actor.last_seen) }}</span>
      </div>
      <ul v-if="actor?.reasons.length" class="id-reasons"><li v-for="r in allReasons ? actor.reasons : actor.reasons.slice(0, 5)" :key="r">{{ r }}</li></ul>
      <button v-if="(actor?.reasons.length ?? 0) > 5" class="linkbtn small" @click="allReasons = !allReasons">{{ allReasons ? 'Fewer reasons' : `All ${actor?.reasons.length} reasons` }}</button>
    </div>
    <div v-if="actor" class="id-side">
      <div class="eyebrow">How deep it got</div>
      <DepthMeter :depth="actor.capability" :tier="actor.depth" size="lg" :color="meta.color" />
      <p class="muted small">0 looked around · 2 used a sample key · 4 used real credentials · 7 exfiltrated</p>
      <button v-if="actor.class !== 'operator'" class="ghost" @click="markOperator">This is my traffic</button>
    </div>
  </section>
  <p v-if="notice" class="muted">{{ notice }}</p>
  <p v-if="error" class="error">{{ error }}</p>
  <StepTimeline :events="events" />
  <div v-if="session" class="card classification">
    <h2>Part of a session across {{ session.members.length }} addresses</h2>
    <p><ClassBadge :cls="session.class" /> · {{ session.links.join('; ') }}</p>
    <p class="mono">
      <template v-for="m in session.members" :key="m">
        <Addr v-if="m !== source" :ip="m" class="member" />
      </template>
    </p>
  </div>
  <div v-if="actor?.links?.length" class="card classification">
    <h2>Linked to known agents ({{ actor.links.length }})</h2>
    <table>
      <thead><tr><th>Agent</th><th>Class</th><th>Last seen</th><th>Through</th></tr></thead>
      <tbody>
        <tr v-for="l in actor.links" :key="l.agent">
          <td class="mono"><RouterLink :to="`/sources/${encodeURIComponent(l.agent)}`">{{ l.agent }}</RouterLink></td>
          <td><ClassBadge :cls="l.class" /></td>
          <td class="muted">{{ l.seen ? fmtTime(l.seen) : '—' }}</td>
          <td>{{ l.via.join(' → ') }}</td>
        </tr>
      </tbody>
    </table>
  </div>
  <div v-if="membership.campaign || membership.cluster" class="card classification">
    <h2>Research</h2>
    <p>
      <span v-if="membership.campaign">Part of campaign <RouterLink to="/research" class="mono">{{ membership.campaign }}</RouterLink>. </span>
      <span v-if="membership.cluster">Behaves like cluster <RouterLink to="/research" class="mono">{{ membership.cluster }}</RouterLink>.</span>
    </p>
  </div>
  <div v-if="actor?.frameworks?.length" class="card classification">
    <h2>Client software (probabilistic)</h2>
    <table>
      <thead><tr><th>Label</th><th>Kind</th><th class="num">Confidence</th><th>Evidence</th></tr></thead>
      <tbody>
        <tr v-for="f in actor.frameworks" :key="f.name">
          <td class="mono">{{ f.name }} <span class="muted">({{ f.level }})</span></td>
          <td>{{ f.kind.replaceAll('_', ' ') }}</td>
          <td class="num">{{ Math.round(f.confidence * 100) }}%</td>
          <td><ul><li v-for="e in f.evidence" :key="e">{{ e }}</li></ul></td>
        </tr>
      </tbody>
    </table>
  </div>
  <div v-if="actor?.features.ssh_connects" class="card classification">
    <h2>SSH node decoy</h2>
    <p>
      {{ actor.features.ssh_connects }} connection(s) ·
      {{ actor.features.ssh_logins ?? 0 }} session(s) opened ·
      {{ actor.features.ssh_auth_fails ?? 0 }} failed login(s)
      <span v-if="actor.features.ssh_client"> · client <span class="mono">{{ actor.features.ssh_client }}</span></span>
    </p>
    <p v-if="actor.features.ssh_usernames?.length"><span class="muted">Usernames tried:</span> <span class="mono">{{ actor.features.ssh_usernames.join(', ') }}</span></p>
    <p v-if="actor.features.ssh_key_fingerprint"><span class="muted">Key fingerprint:</span> <span class="mono">{{ actor.features.ssh_key_fingerprint }}</span></p>
    <p v-if="actor.features.ssh_exfil_url"><span class="muted">Tried to reach:</span> <span class="mono">{{ actor.features.ssh_exfil_url }}</span></p>
    <template v-if="actor.features.ssh_commands?.length">
      <p class="muted">Commands run in the node shell:</p>
      <pre class="mono commands">{{ actor.features.ssh_commands.join('\n') }}</pre>
    </template>
  </div>
  <div class="grid cols-2">
    <div class="card">
      <h2>Incident</h2>
      <template v-if="incident">
        <p><SeverityBadge :severity="incident.severity" /> · score {{ incident.score }} · stages {{ incident.stages.join(', ') }}</p>
        <p class="muted">First seen {{ fmtTime(incident.first_seen) }} · last seen {{ fmtTime(incident.last_seen) }}</p>
        <p v-if="incident.out_of_band || incident.cross_spoke || incident.relayed">
          <span v-if="incident.relayed">Used a key that was revealed to a different address. </span>
          <span v-if="incident.out_of_band">Used a canary it was never shown here. </span>
          <span v-if="incident.cross_spoke">Canary came from another spoke.</span>
        </p>
      </template>
      <p v-else class="muted">No canary activity from this source.</p>
    </div>
    <div class="card">
      <h2>Client traits</h2>
      <p><span class="muted">Surfaces:</span> {{ summary.surfaces.join(', ') || '—' }}</p>
      <p><span class="muted">JA4:</span> <span class="mono">{{ summary.ja4s.join(', ') || '—' }}</span></p>
      <p class="muted">User agents:</p>
      <ul><li v-for="u in summary.uas" :key="u" class="mono">{{ u }}</li></ul>
    </div>
  </div>
  <div v-if="replays.length" class="card payloads">
    <h2>Session recordings ({{ replays.length }})</h2>
    <table>
      <thead><tr><th>Started</th><th>Surface</th><th class="num">Duration</th><th class="num">Size</th><th></th></tr></thead>
      <tbody>
        <tr v-for="rp in replays" :key="rp.view_id">
          <td class="muted">{{ fmtTime(rp.start) }}</td>
          <td>{{ rp.surface }}</td>
          <td class="num">{{ Math.max(1, Math.round((new Date(rp.end).getTime() - new Date(rp.start).getTime()) / 1000)) }}s</td>
          <td class="num">{{ Math.round(rp.bytes / 1024) }} KB</td>
          <td><RouterLink :to="`/replays/${rp.view_id}`">Watch</RouterLink></td>
        </tr>
      </tbody>
    </table>
  </div>
  <div v-if="payloads.length" class="card payloads">
    <h2>Payloads ({{ payloads.length }})</h2>
    <details v-for="p in payloads" :key="p.id" open>
      <summary class="mono">{{ fmtTime(p.time) }} · {{ p.method }} {{ p.surface }}{{ p.path }}<span v-if="p.truncated" class="muted"> (truncated)</span></summary>
      <pre class="mono">{{ p.body }}</pre>
    </details>
  </div>
  <div class="card timeline">
    <h2>Timeline ({{ events.length }} events, newest first)</h2>
    <EventTable :events="events" />
  </div>
</template>

<style scoped>
.grid { margin-bottom: 16px; }
p { margin: 0 0 8px; }
ul { margin: 0; padding-left: 18px; }
.crumbs { margin: -6px 0 10px; }
.id-card { display: grid; grid-template-columns: minmax(0, 1fr) 300px; gap: 28px; padding: 24px 26px; margin-bottom: 16px; border-top: 4px solid var(--cc);
  background: linear-gradient(135deg, color-mix(in srgb, var(--cc) 6%, var(--surface-1)), var(--surface-1) 60%); }
.id-top { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; }
.id-ip { font-size: 26px; margin: 10px 0 2px; }
.id-ip :deep(.addr) { font-size: 24px; font-weight: 650; }
.id-where { margin: 0 0 12px; }
.id-chips { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 14px; }
.id-chips a.pill:hover { text-decoration: none; color: var(--text-primary); }
.ua-pill { max-width: 360px; overflow: hidden; text-overflow: ellipsis; }
.id-reasons { margin: 0; padding-left: 18px; color: var(--text-secondary); display: grid; gap: 3px; }
.id-side { display: grid; gap: 10px; align-content: start; align-self: start; padding: 16px 18px; border-radius: 10px; background: var(--surface-1); border: 1px solid var(--border); }
.id-side p { margin: 0; }
.eyebrow { font-size: 11.5px; font-weight: 700; letter-spacing: 1px; text-transform: uppercase; color: var(--text-muted); }
.linkbtn { background: none; border: 0; color: var(--accent); padding: 6px 0 0; }
button.ghost { justify-self: start; background: transparent; font-size: 12.5px; color: var(--text-secondary); }
@media (max-width: 1000px) { .id-card { grid-template-columns: 1fr; } }
.classification { margin-bottom: 16px; }
.member { margin-right: 10px; }
.payloads { margin-bottom: 16px; }
.payloads details { margin-bottom: 10px; }
.payloads summary { cursor: pointer; color: var(--text-secondary); }
.commands { margin: 0; padding: 10px; background: var(--surface-2); border-radius: 6px; white-space: pre-wrap; max-height: 320px; overflow: auto; }
.payloads pre { margin: 6px 0 0; padding: 10px; background: var(--surface-2); border-radius: 6px; white-space: pre-wrap; word-break: break-word; max-height: 420px; overflow: auto; }
</style>
