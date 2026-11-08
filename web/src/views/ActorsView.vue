<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { api, type Actor, type ActorClass, type Actors } from '../api'
import { pulse, refreshTick, windowHours } from '../state'
import { CLASSES } from '../classes'
import { ago, fmtNum } from '../format'
import ClassBadge from '../components/ClassBadge.vue'
import Addr from '../components/Addr.vue'
import DepthMeter from '../components/DepthMeter.vue'

const route = useRoute()
const data = ref<Actors | null>(null)
const error = ref('')
// Clicking a class card on Overview lands here with ?class=<key> preselected.
const filter = ref<ActorClass | ''>((route.query['class'] as ActorClass) ?? '')
watch(() => route.query['class'], (c) => { filter.value = (c as ActorClass) ?? '' })
const query = ref('')
const expanded = ref<string | null>(null)

async function load(): Promise<void> {
  try {
    data.value = await api.actors(windowHours.value)
    pulse.value = { ...pulse.value, rogue: data.value.summary.rogue_agent ?? 0 }
    error.value = ''
  } catch (e) {
    error.value = (e as Error).message
  }
}
watch([windowHours, refreshTick], load, { immediate: true })

const rows = computed<Actor[]>(() => {
  const q = query.value.trim().toLowerCase()
  return (data.value?.actors ?? []).filter(
    (a) =>
      (filter.value ? a.class === filter.value : a.class !== 'operator') &&
      (!q || a.source.includes(q) || (a.hostname ?? '').includes(q) || (a.network ?? '').toLowerCase().includes(q) || (a.country ?? '').toLowerCase().includes(q) || (a.country_code ?? '').toLowerCase() === q || (a.user_agents ?? []).some((u) => u.toLowerCase().includes(q)) || (a.ja4 ?? []).some((j) => j.includes(q))),
  )
})
const byIP = computed(() => new Map<string, Actor>((data.value?.actors ?? []).map((a) => [a.source, a])))
const sessions = computed(() => (data.value?.sessions ?? []).filter((s) => s.class !== 'operator'))
const total = computed(() => (data.value?.actors ?? []).filter((a) => a.class !== 'operator').length)
</script>

<template>
  <h1>Actors</h1>
  <p class="page-intro">Every address in the window, classified by what it did rather than what it claimed. Pick a class to focus; click a row for detail.</p>
  <p v-if="error" class="error">{{ error }}</p>

  <div v-if="data" class="tiles">
    <button v-for="c in CLASSES" :key="c.key" class="card tile" :style="{ '--cc': c.color }" :class="{ active: filter === c.key, rogue: c.key === 'rogue_agent' && (data.summary[c.key] ?? 0) > 0 }"
      @click="filter = filter === c.key ? '' : c.key" :aria-pressed="filter === c.key">
      <span class="t-head"><span :style="{ color: c.color }" aria-hidden="true">{{ c.icon }}</span> {{ c.plural }}</span>
      <span class="t-n">{{ fmtNum(data.summary[c.key] ?? 0) }}</span>
      <span class="t-blurb muted">{{ c.blurb }}</span>
    </button>
  </div>

  <div v-if="sessions.length" class="card sessions">
    <h2>Multi-address sessions ({{ sessions.length }})</h2>
    <p class="muted small">Addresses joined because they are one client: a key or agent ID carried between them, or the same client (user agent and TLS stack) on the same network at the same moment.</p>
    <div class="table-wrap"><table>
      <thead><tr><th>Class</th><th class="num">Addresses</th><th>Members</th><th>Why joined</th><th>User agent</th><th>Last seen</th></tr></thead>
      <tbody>
        <tr v-for="s in sessions" :key="s.id" :class="{ rogue: s.class === 'rogue_agent' }">
          <td><ClassBadge :cls="s.class" /></td>
          <td class="num">{{ s.members.length }}</td>
          <td class="mono members iplist">
            <Addr v-for="m in s.members.slice(0, 8)" :key="m" :ip="m" :cc="byIP.get(m)?.country_code" :country="byIP.get(m)?.country" />
            <span v-if="s.members.length > 8" class="muted">+{{ s.members.length - 8 }} more</span>
          </td>
          <td class="why">{{ s.links.join('; ') }}</td>
          <td class="truncate muted" :title="s.user_agent ?? ''">{{ s.user_agent || '—' }}</td>
          <td class="muted nowrap">{{ ago(s.last_seen) }}</td>
        </tr>
      </tbody>
    </table></div>
  </div>

  <div class="row controls">
    <input v-model="query" placeholder="Filter by IP, network, country, user agent or JA4" aria-label="Filter" />
    <span class="muted">{{ fmtNum(rows.length) }} of {{ fmtNum(total) }} sources</span>
    <button v-if="filter" @click="filter = ''">Show all classes</button>
  </div>

  <div class="card table-wrap">
    <table>
      <thead>
        <tr><th>Class</th><th>Source</th><th>Where</th><th class="num">Score</th><th class="num">Requests</th><th title="How deep into the estate the actor reached (0-7)">Depth</th><th>Why</th><th>User agent</th><th>Last seen</th></tr>
      </thead>
      <tbody>
        <template v-for="a in rows" :key="a.source">
          <tr class="clickable" :class="{ rogue: a.class === 'rogue_agent' }" @click="expanded = expanded === a.source ? null : a.source">
            <td><ClassBadge :cls="a.class" :confidence="a.confidence" /></td>
            <td class="nowrap"><Addr :ip="a.source" :cc="a.country_code" :country="a.country" />
              <span v-if="a.session_size" class="sess" :title="`One of ${a.session_size} addresses in a session`">+{{ a.session_size - 1 }}</span></td>
            <td class="net" :title="a.hostname ?? ''"><span class="truncate-1">{{ a.country || '—' }}</span>
              <span v-if="a.network" class="muted small truncate-1">{{ a.network }}<span v-if="a.crawler_check === 'verified'" title="Verified crawler"> ✓</span></span></td>
            <td class="num">{{ a.score }}</td>
            <td class="num">{{ fmtNum(a.features.requests) }}</td>
            <td><DepthMeter :depth="a.capability" :tier="a.depth" size="sm" :color="a.class === 'rogue_agent' ? 'var(--c-rogue)' : 'var(--c-agent)'" /></td>
            <td class="why">{{ a.reasons[0] }}<span v-if="a.reasons.length > 1" class="muted"> +{{ a.reasons.length - 1 }}</span></td>
            <td class="truncate muted ua" :title="(a.user_agents ?? []).join('\n')">{{ (a.user_agents ?? [])[0] ?? '—' }}</td>
            <td class="muted nowrap">{{ ago(a.last_seen) }}</td>
          </tr>
          <tr v-if="expanded === a.source" class="detail">
            <td colspan="9">
              <div class="grid cols-2">
                <div>
                  <h2>Reasons</h2>
                  <ul><li v-for="r in a.reasons" :key="r">{{ r }}</li></ul>
                </div>
                <div>
                  <h2>Behavior</h2>
                  <p class="facts depth-line">
                    <DepthMeter :depth="a.capability" :tier="a.depth" size="lg" :color="a.class === 'rogue_agent' ? 'var(--c-rogue)' : 'var(--c-agent)'" /><span v-if="a.features.max_stage"> · credential chain stage {{ a.features.max_stage }}</span>
                  </p>
                  <p class="facts">
                    {{ a.features.distinct_paths }} paths · {{ a.features.surfaces }} surfaces ·
                    {{ a.features.wordlist_hits }} scanner paths · {{ a.features.not_found }} not found ·
                    median gap {{ (a.features.median_gap_ms / 1000).toFixed(1) }}s ·
                    MCP {{ a.features.mcp_initialize ? 'initialize ' : '' }}{{ a.features.mcp_tools_list ? 'tools/list ' : '' }}{{ a.features.mcp_tool_calls }} call(s) ·
                    {{ a.features.llm_calls }} API call(s) · declared as {{ a.features.declared_as }}
                  </p>
                  <p v-if="a.ja4?.length" class="mono">JA4: {{ a.ja4.join(', ') }}</p>
                </div>
              </div>
            </td>
          </tr>
        </template>
      </tbody>
    </table>
    <p v-if="!rows.length" class="empty">No sources match.</p>
    <p v-if="rows.some((a) => a.country_code)" class="muted small geo-credit">Country flags: IP geolocation by <a href="https://db-ip.com" target="_blank" rel="noopener">DB-IP</a></p>
  </div>
</template>

<style scoped>
.geo-credit { margin: 8px 0 0; }
.tiles { display: grid; grid-template-columns: repeat(7, minmax(0, 1fr)); gap: 12px; margin-bottom: 16px; }
@media (max-width: 1100px) { .tiles { grid-template-columns: repeat(3, minmax(0, 1fr)); } }
@media (max-width: 600px) { .tiles { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
.tile { display: grid; gap: 2px; text-align: left; cursor: pointer; color: var(--text-primary); border-top: 3px solid var(--cc); transition: box-shadow 0.15s, transform 0.15s, background-color 0.15s; }
.tile:hover { box-shadow: var(--shadow-hover); transform: translateY(-1px); border-color: var(--border); border-top-color: var(--cc); }
.tile.active { background: color-mix(in srgb, var(--cc) 9%, var(--surface-1)); outline: 2px solid var(--cc); outline-offset: -1px; }
.tile.rogue .t-n { color: var(--c-rogue); }
.t-head { color: var(--text-secondary); font-size: 12.5px; font-weight: 500; }
.t-n { font-size: 26px; font-weight: 700; font-variant-numeric: tabular-nums; letter-spacing: -0.4px; }
.t-blurb { font-size: 11.5px; }
.controls { margin-bottom: 12px; }
.controls input { min-width: 280px; }
.why { min-width: 260px; max-width: 420px; }
.ua { max-width: 200px; }
.net { max-width: 190px; }
.truncate-1 { display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.sessions { margin-bottom: 16px; }
p.small { font-size: 12.5px; margin: -4px 0 8px; }
.members { min-width: 300px; }
.members .addr { display: inline-block; margin: 0 12px 4px 0; }
.sess { display: inline-block; margin-left: 6px; padding: 0 6px; border-radius: 8px; font-size: 11px; background: var(--surface-2); border: 1px solid var(--border); color: var(--text-secondary); }
.nowrap { white-space: nowrap; }
tr.clickable { cursor: pointer; }
tr.clickable:hover td { background: var(--surface-2); }
tr.rogue td { background: color-mix(in srgb, var(--c-rogue) 6%, transparent); }
tr.rogue td:first-child { box-shadow: inset 3px 0 0 var(--c-rogue); }
tr.detail td { background: var(--surface-2); }
.facts { margin: 0 0 8px; color: var(--text-secondary); }
.depth-line { color: var(--text-primary); }
.dtag { display: inline-block; min-width: 30px; text-align: center; padding: 1px 6px; border-radius: 6px; font-variant-numeric: tabular-nums; font-size: 12px; background: var(--surface-2); border: 1px solid var(--border); }
.dtag[data-d='3'], .dtag[data-d='4'] { border-color: color-mix(in srgb, var(--accent) 55%, var(--border)); color: var(--accent); }
.dtag[data-d='5'], .dtag[data-d='6'] { border-color: #f59e0b88; color: #f59e0b; }
.dtag[data-d='7'] { border-color: color-mix(in srgb, var(--critical) 60%, var(--border)); color: var(--critical); background: color-mix(in srgb, var(--critical) 10%, transparent); }
ul { margin: 0; padding-left: 18px; }
</style>
