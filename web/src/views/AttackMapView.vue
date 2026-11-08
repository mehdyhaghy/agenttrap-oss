<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import * as echarts from 'echarts/core'
import { GeoComponent, TooltipComponent } from 'echarts/components'
import { EffectScatterChart, ScatterChart } from 'echarts/charts'
import { CanvasRenderer } from 'echarts/renderers'
import type { EChartsCoreOption } from 'echarts/core'
import { feature } from 'topojson-client'
// world-atlas ships a public-domain Natural Earth countries TopoJSON; ECharts
// renders it as the base map, so no d3/tile dependency is needed.
import worldTopo from 'world-atlas/countries-110m.json'
import { api, type AttackMap, type AttackReplay, type MapPoint, type ReplayCell } from '../api'
import { refreshTick, windowHours } from '../state'
import { VISITOR_CLASSES } from '../classes'
import { flag, fmtMinute, fmtNum } from '../format'
import StatTile from '../components/StatTile.vue'
import ReplayScrubber from '../components/ReplayScrubber.vue'

echarts.use([GeoComponent, TooltipComponent, EffectScatterChart, ScatterChart, CanvasRenderer])
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const world = feature(worldTopo as any, (worldTopo as any).objects.countries)
echarts.registerMap('world', world as never)

const data = ref<AttackMap | null>(null)
const error = ref('')
const el = ref<HTMLDivElement | null>(null)
let chart: echarts.ECharts | undefined
let observer: ResizeObserver | undefined
const media = window.matchMedia('(prefers-color-scheme: dark)')
const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)')

// Filters: a from/to range (seeded from the global window), a per-class set and
// a city/country granularity toggle.
const fromDt = ref('')
const toDt = ref('')
const selected = ref<Set<string>>(new Set(VISITOR_CLASSES.map((c) => c.key)))
const granularity = ref<'city' | 'country'>('city')
const view = ref<'snapshot' | 'replay'>('snapshot')

const classColor: Record<string, string> = {
  rogue_agent: '#ef4444',
  ai_agent: '#f59e0b',
  scanner: '#eab308',
  crawler: '#64748b',
  browser: '#3b82f6',
  unknown: '#94a3b8',
}
const classLabel = (c: string): string => c.replace(/_/g, ' ')

function dtLocal(d: Date): string {
  const p = (n: number): string => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`
}
const unix = (s: string): number | undefined => (s ? Math.floor(new Date(s).getTime() / 1000) : undefined)

// Reset the range to the global window (also on first load and when it changes).
function syncWindow(): void {
  toDt.value = dtLocal(new Date())
  fromDt.value = dtLocal(new Date(Date.now() - windowHours.value * 3600_000))
}
const activeClasses = computed(() =>
  selected.value.size === 0 || selected.value.size === VISITOR_CLASSES.length ? undefined : [...selected.value],
)
function toggleClass(key: string): void {
  const s = new Set(selected.value)
  s.has(key) ? s.delete(key) : s.add(key)
  selected.value = s
}

async function load(): Promise<void> {
  try {
    const q = { from: unix(fromDt.value), to: unix(toDt.value), classes: activeClasses.value }
    const [snap, rep] = await Promise.all([api.attackMap(q), view.value === 'replay' ? api.attackReplay(q) : Promise.resolve(null)])
    data.value = snap
    if (rep) setReplay(rep)
    error.value = ''
    render()
  } catch (e) {
    error.value = (e as Error).message
  }
}

// ---- Replay: the range played back frame by frame (Kepler.gl-style). ----
const replay = ref<AttackReplay | null>(null)
const frame = ref(0)
const playing = ref(false)
const speed = ref(1)
const loop = ref(false)
const mode = ref<'trail' | 'cumulative'>('trail')
const TRAIL = 8 // frames a point takes to fade out in trail mode
const FRAME_MS = 650 // at 1x
let byFrame: ReplayCell[][] = []

function setReplay(r: AttackReplay): void {
  playing.value = false
  replay.value = r
  byFrame = Array.from({ length: r.frames }, () => [])
  for (const c of r.cells) byFrame[c.f]?.push(c)
  // Start on the first frame with located activity, so the map is never blank.
  const firstBusy = byFrame.findIndex((cells) => cells.length > 0)
  frame.value = Math.max(0, firstBusy)
}

// Places grouped for the current granularity: a country uses its first city's
// coordinates, as the snapshot's country rollup does.
const groups = computed(() => {
  const r = replay.value
  if (!r) return { of: [] as number[], list: [] as { lat: number; lon: number; label: string; cc?: string }[] }
  const key = new Map<string, number>()
  const of: number[] = []
  const list: { lat: number; lon: number; label: string; cc?: string }[] = []
  for (const p of r.places) {
    const k = granularity.value === 'country' ? p.country_code || '?' : `${p.country_code}|${p.city}`
    let g = key.get(k)
    if (g === undefined) {
      g = list.length
      key.set(k, g)
      const label = granularity.value === 'country' ? p.country || p.country_code || 'unknown' : [p.city, p.country].filter(Boolean).join(', ') || 'unknown'
      list.push({ lat: p.lat, lon: p.lon, label, ...(p.country_code ? { cc: p.country_code } : {}) })
    }
    of.push(g)
  }
  return { of, list }
})

interface FramePoint { g: number; last: number; actors: number; fresh: number; events: number; score: number; cls: string; sources: string[] }

// What each place shows at the current frame: its activity over the trail (or
// everything so far), its worst actor, and when it was last active.
const framePoints = computed<FramePoint[]>(() => {
  const r = replay.value
  if (!r) return []
  const lo = mode.value === 'cumulative' ? 0 : Math.max(0, frame.value - TRAIL + 1)
  const by = new Map<number, FramePoint>()
  for (let f = lo; f <= frame.value; f++) {
    for (const c of byFrame[f] ?? []) {
      const g = groups.value.of[c.p] ?? 0
      let pt = by.get(g)
      if (!pt) {
        pt = { g, last: f, actors: 0, fresh: 0, events: 0, score: -1, cls: c.c, sources: [] }
        by.set(g, pt)
      }
      pt.last = f
      pt.events += c.e
      // Cumulative counts distinct actors exactly (each is new once); the
      // trail sizes a place by its busiest frame in view.
      pt.actors = mode.value === 'cumulative' ? pt.actors + c.n : Math.max(pt.actors, c.a)
      if (f === frame.value) pt.fresh += c.n
      if (c.s >= pt.score) { pt.score = c.s; pt.cls = c.c }
      for (const s of c.src ?? []) if (pt.sources.length < 4 && !pt.sources.includes(s)) pt.sources.push(s)
    }
  }
  return [...by.values()].sort((a, b) => a.score - b.score)
})

const frameStats = computed(() => {
  const now = byFrame[frame.value] ?? []
  return {
    places: new Set(now.map((c) => groups.value.of[c.p])).size,
    actors: now.reduce((t, c) => t + c.a, 0),
    fresh: now.reduce((t, c) => t + c.n, 0),
    events: replay.value?.activity[frame.value] ?? 0,
  }
})
const frameLabel = computed(() => {
  const r = replay.value
  if (!r) return ''
  const start = new Date(r.since).getTime() + frame.value * r.step_seconds * 1000
  const end = Math.min(start + r.step_seconds * 1000, new Date(r.until).getTime())
  return `${fmtMinute(start)} – ${new Date(end).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })}`
})

function replayOption(): EChartsCoreOption {
  const list = groups.value.list
  const row = (pt: FramePoint) => {
    const g = list[pt.g]
    const age = frame.value - pt.last
    const size = Math.min(34, 6 + Math.sqrt(pt.actors) * 4)
    const fade = mode.value === 'cumulative' ? 0.55 : Math.max(0.12, 1 - age / TRAIL)
    return {
      name: String(pt.g), // stable per place, so updates animate instead of redraw
      value: [g?.lon ?? 0, g?.lat ?? 0, pt.actors],
      symbolSize: age === 0 ? size : size * (mode.value === 'cumulative' ? 1 : 0.85),
      itemStyle: { color: classColor[pt.cls] ?? classColor['unknown'], opacity: age === 0 ? 0.95 : fade },
      pt,
    }
  }
  const now = framePoints.value.filter((p) => p.last === frame.value).map(row)
  const past = framePoints.value.filter((p) => p.last !== frame.value).map(row)
  return {
    series: [
      { id: 'attacks', type: 'effectScatter', coordinateSystem: 'geo', data: [], zlevel: 1 },
      { id: 'trail', type: 'scatter', coordinateSystem: 'geo', data: past, zlevel: 1, animationDurationUpdate: 250 },
      {
        id: 'now', type: 'effectScatter', coordinateSystem: 'geo', data: now, zlevel: 2,
        showEffectOn: 'render',
        rippleEffect: reducedMotion.matches ? { scale: 1, number: 0 } : { brushType: 'stroke', scale: 2.6, period: 2 },
        animationDurationUpdate: 250,
      },
    ],
  }
}

// The tooltip is HTML: escape every value that comes from recorded data.
function esc(v: string): string {
  return v.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`)
}

function tooltip(o: { data?: { p?: MapPoint; pt?: FramePoint } }): string {
  const p = o.data?.p
  if (p) {
    const where = esc([flag(p.country_code), [p.city, p.country].filter(Boolean).join(', ') || 'unknown'].filter(Boolean).join(' '))
    const src = esc((p.sources ?? []).slice(0, 4).join(', '))
    return `<b>${where}</b><br/>${p.count} actor(s) · top: ${classLabel(p.top_class)} (score ${p.score})${src ? `<br/><span style="opacity:.7">${src}</span>` : ''}`
  }
  const pt = o.data?.pt
  if (!pt) return ''
  const g = groups.value.list[pt.g]
  const age = frame.value - pt.last
  const when = age === 0 ? 'active now' : `last active ${age} frame${age === 1 ? '' : 's'} ago`
  const fresh = pt.fresh ? ` · <b>${pt.fresh} new</b>` : ''
  return `<b>${esc(`${flag(g?.cc)} ${g?.label ?? ''}`)}</b><br/>${when} · ${pt.actors} actor(s)${fresh} · ${fmtNum(pt.events)} events<br/>` +
    `top: ${classLabel(pt.cls)} (score ${pt.score})${pt.sources.length ? `<br/><span style="opacity:.7">${esc(pt.sources.join(', '))}</span>` : ''}`
}

// Playback clock: one frame per FRAME_MS / speed.
let playTimer: number | undefined
watch([playing, speed], () => {
  window.clearInterval(playTimer)
  if (!playing.value) return
  playTimer = window.setInterval(() => {
    const n = replay.value?.frames ?? 0
    if (frame.value < n - 1) frame.value++
    else if (loop.value) frame.value = 0
    else playing.value = false
  }, FRAME_MS / speed.value)
})

// Space plays/pauses, arrows step (Shift: 10 frames), Home/End jump.
function onKey(e: KeyboardEvent): void {
  if (view.value !== 'replay' || !replay.value) return
  const t = e.target instanceof Element ? e.target : null
  if (t && (t.closest('input, textarea, select, [contenteditable]') || (t.tagName === 'BUTTON' && e.key === ' '))) return
  const n = replay.value.frames
  const step = e.shiftKey ? 10 : 1
  if (e.key === ' ') { if (!playing.value && frame.value >= n - 1) frame.value = 0; playing.value = !playing.value }
  else if (e.key === 'ArrowRight') { playing.value = false; frame.value = Math.min(n - 1, frame.value + step) }
  else if (e.key === 'ArrowLeft') { playing.value = false; frame.value = Math.max(0, frame.value - step) }
  else if (e.key === 'Home') frame.value = 0
  else if (e.key === 'End') frame.value = n - 1
  else return
  e.preventDefault()
}

const shown = computed<MapPoint[]>(() =>
  (granularity.value === 'country' ? data.value?.countries : data.value?.points) ?? [],
)

function option(points: MapPoint[]): EChartsCoreOption {
  const dark = media.matches
  const rows = points.map((p) => ({
    name: p.city || p.country || `${p.lat.toFixed(1)},${p.lon.toFixed(1)}`,
    value: [p.lon, p.lat, p.count],
    itemStyle: { color: classColor[p.top_class] ?? classColor['unknown'] },
    p,
  }))
  return {
    backgroundColor: 'transparent',
    tooltip: {
      trigger: 'item',
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      formatter: (o: any): string => tooltip(o),
    },
    geo: {
      map: 'world',
      roam: true,
      silent: true,
      itemStyle: { areaColor: dark ? '#242a36' : '#e9edf3', borderColor: dark ? '#39414f' : '#cbd2dd', borderWidth: 0.5 },
    },
    series: [
      {
        id: 'attacks',
        name: 'attacks',
        type: 'effectScatter',
        coordinateSystem: 'geo',
        data: rows,
        symbolSize: (v: number[]): number => Math.min(34, 6 + Math.sqrt(v[2] ?? 0) * 4),
        rippleEffect: { brushType: 'stroke', scale: 2.2 },
        zlevel: 1,
      },
    ],
  }
}

function render(): void {
  if (!el.value || !data.value?.enabled) return
  if (!chart) chart = echarts.init(el.value, undefined, { renderer: 'canvas' })
  if (view.value === 'replay' && replay.value) {
    chart.setOption({ ...option([]), ...replayOption() }, { notMerge: true })
  } else {
    chart.setOption(option(shown.value), { notMerge: true })
  }
}
// Frame changes only swap series data, keeping the map, zoom and pan.
function renderFrame(): void {
  if (chart && view.value === 'replay' && replay.value) chart.setOption(replayOption(), { lazyUpdate: true })
}
watch([frame, mode], renderFrame)

const topCountries = computed(() => (data.value?.countries ?? []).slice(0, 10))
const stepLabel = computed(() => {
  const s = replay.value?.step_seconds ?? 0
  return s >= 86400 ? `${s / 86400} day` : s >= 3600 ? `${s / 3600} h` : `${s / 60} min`
})

onMounted(() => {
  syncWindow()
  media.addEventListener('change', render)
  window.addEventListener('keydown', onKey)
  observer = new ResizeObserver(() => chart?.resize())
  if (el.value) observer.observe(el.value)
  void load()
})
// The global window selector reseeds the range; explicit filters reload.
watch(windowHours, () => { syncWindow(); void load() })
watch([fromDt, toDt, activeClasses], load)
// Auto-refresh would restart playback, so it only refreshes the snapshot.
watch(refreshTick, () => { if (view.value === 'snapshot') void load() })
watch(view, () => { if (view.value === 'replay' && !replay.value) void load(); else { playing.value = false; render() } })
watch(granularity, render)
onBeforeUnmount(() => {
  window.clearInterval(playTimer)
  window.removeEventListener('keydown', onKey)
  observer?.disconnect()
  media.removeEventListener('change', render)
  chart?.dispose()
})
</script>

<template>
  <h1>Attack map</h1>
  <p class="muted note">
    Where attacker traffic comes from over the chosen range. Operators and unroutable addresses are excluded; a point's
    colour is the class of the worst actor there, and its size grows with how many actors share it.
  </p>
  <p v-if="error" class="error">{{ error }}</p>

  <div v-if="data && !data.enabled" class="card section">
    <p>
      The attack map is disabled: no geolocation database is mounted. Add <code>DB-IP Lite City</code> (MMDB) as described
      in <code>deploy/geo/README.md</code>, then restart the hub.
    </p>
  </div>

  <template v-else>
    <div class="card controls">
      <label>From <input type="datetime-local" v-model="fromDt" /></label>
      <label>To <input type="datetime-local" v-model="toDt" /></label>
      <span class="sep" aria-hidden="true"></span>
      <div class="classes" role="group" aria-label="Filter by class">
        <button v-for="c in VISITOR_CLASSES" :key="c.key" type="button" class="chip"
          :class="{ off: !selected.has(c.key) }" :style="{ '--c': c.color }" :aria-pressed="selected.has(c.key)"
          @click="toggleClass(c.key)">
          <span aria-hidden="true">{{ c.icon }}</span> {{ c.plural }}
        </button>
      </div>
      <span class="sep" aria-hidden="true"></span>
      <div class="seg" role="group" aria-label="View">
        <button type="button" :class="{ active: view === 'snapshot' }" :aria-pressed="view === 'snapshot'" @click="view = 'snapshot'">Snapshot</button>
        <button type="button" :class="{ active: view === 'replay' }" :aria-pressed="view === 'replay'" @click="view = 'replay'">▶ Replay</button>
      </div>
      <span class="sep" aria-hidden="true"></span>
      <div class="seg" role="group" aria-label="Granularity">
        <button type="button" :class="{ active: granularity === 'city' }" @click="granularity = 'city'">Cities</button>
        <button type="button" :class="{ active: granularity === 'country' }" @click="granularity = 'country'">Countries</button>
      </div>
    </div>

    <div class="grid cols-3 tiles">
      <StatTile label="Located actors" :value="fmtNum(data?.mapped ?? 0)" :hint="`of ${fmtNum(data?.actors ?? 0)} in range`" />
      <StatTile label="Cities" :value="fmtNum(data?.points?.length ?? 0)" :hint="`${data?.countries?.length ?? 0} countries`" />
      <StatTile label="Loudest" :value="String(data?.points?.[data.points.length - 1]?.score ?? 0)" hint="top agent-likeness score" />
    </div>

    <div class="grid map-row">
      <div class="card section">
        <div class="map-wrap">
          <div ref="el" role="img" aria-label="World map of attack origins" style="height: 560px; width: 100%"></div>
          <!-- The time sits on the map so the eye need not leave it (split attention). -->
          <div v-if="view === 'replay' && replay" class="now" aria-live="off">
            <div class="when">{{ frameLabel }}</div>
            <div class="what">
              {{ frameStats.actors }} actor{{ frameStats.actors === 1 ? '' : 's' }} in {{ frameStats.places }} place{{ frameStats.places === 1 ? '' : 's' }}
              <template v-if="frameStats.fresh"> · <b>{{ frameStats.fresh }} new</b></template>
              · {{ fmtNum(frameStats.events) }} events
            </div>
          </div>
          <div v-if="view === 'replay' && !replay" class="now"><div class="what">Loading replay…</div></div>
        </div>
        <ReplayScrubber v-if="view === 'replay' && replay && replay.frames > 0" v-model:frame="frame" v-model:playing="playing"
          v-model:speed="speed" v-model:loop="loop" v-model:mode="mode" :activity="replay.activity" :since="replay.since"
          :step-seconds="replay.step_seconds" />
        <p v-if="view === 'replay' && replay" class="muted hint">
          {{ fmtNum(replay.mapped) }} located actors in {{ replay.frames }} frames of {{ stepLabel }} · the histogram shows all
          events (click or drag to seek) · Space plays, ←/→ step, Shift+←/→ jump 10 · times in your time zone
        </p>
        <p class="muted attribution">{{ data?.attribution ?? 'IP geolocation by DB-IP' }} · <a href="https://db-ip.com" target="_blank" rel="noopener">db-ip.com</a></p>
      </div>
      <div class="card section">
        <h2>Top countries</h2>
        <table>
          <thead><tr><th>Country</th><th class="num">Actors</th><th class="num">Top score</th></tr></thead>
          <tbody>
            <tr v-for="c in topCountries" :key="c.country_code">
              <td><span :style="{ color: classColor[c.top_class] ?? classColor['unknown'] }" aria-hidden="true">●</span> {{ flag(c.country_code) }} {{ c.country || c.country_code || '—' }}</td>
              <td class="num">{{ fmtNum(c.count) }}</td>
              <td class="num">{{ c.score }}</td>
            </tr>
          </tbody>
        </table>
        <p v-if="!topCountries.length" class="empty">No located actors in range.</p>
      </div>
    </div>
  </template>
</template>

<style scoped>
.controls { display: flex; flex-wrap: wrap; align-items: center; gap: 10px 12px; margin-bottom: 16px; }
.controls label { display: inline-flex; align-items: center; gap: 6px; font-size: 12.5px; color: var(--text-secondary); }
.sep { width: 1px; align-self: stretch; background: var(--border); margin: 0 2px; }
.classes { display: flex; flex-wrap: wrap; gap: 6px; }
.chip { display: inline-flex; align-items: center; gap: 5px; padding: 4px 9px; font-size: 12px; border-radius: 999px; border-color: color-mix(in srgb, var(--c) 55%, var(--border)); }
.chip span[aria-hidden] { color: var(--c); }
.chip.off { opacity: 0.4; }
.seg { display: inline-flex; border: 1px solid var(--border); border-radius: 6px; overflow: hidden; }
.seg button { border: 0; border-radius: 0; background: var(--surface-2); padding: 5px 12px; }
.seg button.active { background: var(--accent); color: #fff; }
.map-row { grid-template-columns: 1fr 320px; gap: 16px; align-items: start; }
@media (max-width: 1000px) { .map-row { grid-template-columns: 1fr; } }
.attribution { margin: 0.5rem 0 0; font-size: 0.8rem; }
.map-wrap { position: relative; }
.now { position: absolute; top: 10px; left: 12px; pointer-events: none; padding: 8px 12px; border-radius: 10px;
  background: color-mix(in srgb, var(--surface-1) 82%, transparent); border: 1px solid var(--border); backdrop-filter: blur(4px); }
.now .when { font-size: 20px; font-weight: 700; letter-spacing: -0.2px; font-variant-numeric: tabular-nums; }
.now .what { font-size: 12.5px; color: var(--text-secondary); margin-top: 2px; }
.hint { font-size: 12px; margin: 6px 0 0; }
.empty { color: var(--text-muted); padding: 12px 0; }
</style>
