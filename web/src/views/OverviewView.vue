<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { api, type Actor, type Actors, type Overview } from '../api'
import { pulse, refreshTick, windowHours } from '../state'
import { ago, cssVar, flag, fmtNum } from '../format'
import BarCell from '../components/BarCell.vue'
import Addr from '../components/Addr.vue'
import DepthMeter from '../components/DepthMeter.vue'
import { VISITOR_CLASSES } from '../classes'
import { verdict, windowLabel } from '../story'
import EChart from '../components/EChart.vue'

const router = useRouter()
const data = ref<Overview | null>(null)
const actors = ref<Actors | null>(null)
const error = ref('')
const themeTick = ref(0)
const allTraps = ref(false)

// Brushing the timeline drills into the events in that window (Splunk-style).
function drill(fromMs: number, toMs: number): void {
  void router.push({ path: '/events', query: { from: Math.floor(fromMs / 1000), to: Math.ceil(toMs / 1000) } })
}

async function load(): Promise<void> {
  try {
    ;[data.value, actors.value] = await Promise.all([api.overview(windowHours.value), api.actors(windowHours.value)])
    const sev = data.value.severity ?? {}
    pulse.value = { rogue: actors.value.summary.rogue_agent ?? 0, urgent: (sev['critical'] ?? 0) + (sev['high'] ?? 0) }
    error.value = ''
  } catch (e) {
    error.value = (e as Error).message
  }
}
watch([windowHours, refreshTick], load, { immediate: true })

const sev = computed(() => data.value?.severity ?? {})
const max = <T,>(rows: T[] | null | undefined, f: (r: T) => number): number =>
  Math.max(0, ...(rows ?? []).map(f))

const story = computed(() => (actors.value && data.value ? verdict(actors.value, data.value.totals.sources, windowLabel(windowHours.value)) : null))
const moodColor = computed(() => ({ rogue: 'var(--c-rogue)', agents: 'var(--c-agent)', quiet: 'var(--c-crawler)' })[story.value?.mood ?? 'quiet'])

// Visitor mix: one stacked bar, every class, operator traffic left out.
const mix = computed(() => {
  const s = actors.value?.summary
  if (!s) return []
  const total = VISITOR_CLASSES.reduce((t, c) => t + (s[c.key] ?? 0), 0) || 1
  return VISITOR_CLASSES.map((c) => ({ ...c, n: s[c.key] ?? 0, pct: (100 * (s[c.key] ?? 0)) / total }))
})

// Traps: stages somebody reached, most-reached first; the rest fold away.
const traps = computed(() => {
  const rows = data.value?.funnel ?? []
  const hit = rows.filter((f) => f.sources > 0)
  return { shown: allTraps.value ? rows : hit, idle: rows.length - hit.length, max: Math.max(1, ...rows.map((f) => f.sources)) }
})

// Countries across every visitor in the window, most first.
const countries = computed(() => {
  const m = new Map<string, { cc: string; name: string; n: number; rogue: number }>()
  for (const a of actors.value?.actors ?? []) {
    if (!a.country_code || a.class === 'operator') continue
    const c = m.get(a.country_code) ?? { cc: a.country_code, name: a.country || a.country_code, n: 0, rogue: 0 }
    c.n++
    if (a.class === 'rogue_agent') c.rogue++
    m.set(a.country_code, c)
  }
  return [...m.values()].sort((x, y) => y.rogue - x.rogue || y.n - x.n).slice(0, 7)
})
const byIP = computed(() => new Map<string, Actor>((actors.value?.actors ?? []).map((a) => [a.source, a])))

function axisStyle() {
  return {
    axisLine: { lineStyle: { color: cssVar('--grid') } },
    axisTick: { show: false },
    axisLabel: { color: cssVar('--text-muted'), fontSize: 11 },
    splitLine: { lineStyle: { color: cssVar('--grid') } },
  }
}
function tooltipStyle() {
  return {
    backgroundColor: cssVar('--surface-1'),
    borderColor: cssVar('--border'),
    textStyle: { color: cssVar('--text-primary'), fontSize: 12 },
  }
}

const timelineOption = computed(() => {
  void themeTick.value
  const rows = data.value?.timeline ?? []
  const color = cssVar('--series-1')
  return {
    animation: false,
    grid: { left: 40, right: 12, top: 12, bottom: 26 },
    tooltip: { trigger: 'axis', axisPointer: { type: 'line', lineStyle: { color: cssVar('--text-muted') } }, ...tooltipStyle(),
      valueFormatter: (v: number) => fmtNum(v) },
    xAxis: { type: 'time', ...axisStyle(), splitLine: { show: false } },
    yAxis: { type: 'value', minInterval: 1, ...axisStyle(), axisLine: { show: false } },
    series: [{
      name: 'Requests', type: 'line', smooth: 0.25, showSymbol: rows.length < 3, symbolSize: 8,
      lineStyle: { width: 2, color }, itemStyle: { color },
      areaStyle: { color: { type: 'linear', x: 0, y: 0, x2: 0, y2: 1, colorStops: [{ offset: 0, color: `${color}40` }, { offset: 1, color: `${color}00` }] } },
      data: rows.map((r) => [r.time, r.requests]),
    }],
  }
})
</script>

<template>
  <p v-if="error" class="error">{{ error }}</p>
  <template v-if="data && actors && story">
    <!-- The verdict: one sentence that says whether the window needs attention. -->
    <section class="hero card" :style="{ '--mood': moodColor }">
      <div class="hero-main">
        <div class="eyebrow">Last {{ windowLabel(windowHours) }}</div>
        <h1>{{ story.headline }}</h1>
        <p class="detail">{{ story.detail }}</p>
        <div class="row ctas">
          <RouterLink v-if="story.mood === 'rogue'" class="cta primary" :to="{ path: '/actors', query: { class: 'rogue_agent' } }">Review rogue agents →</RouterLink>
          <RouterLink v-else-if="story.mood === 'agents'" class="cta primary" :to="{ path: '/actors', query: { class: 'ai_agent' } }">See the AI agents →</RouterLink>
          <RouterLink v-if="(sev['critical'] ?? 0) + (sev['high'] ?? 0) > 0" class="cta" to="/incidents">Open incidents</RouterLink>
          <RouterLink class="cta" to="/map">Attack map</RouterLink>
        </div>
      </div>
      <RouterLink v-if="story.deepest" class="deepest" :to="`/sources/${encodeURIComponent(story.deepest.source)}`">
        <div class="eyebrow muted">Deepest intrusion</div>
        <div class="d-ip"><Addr :ip="story.deepest.source" :cc="story.deepest.country_code" :country="story.deepest.country" :link="false" /></div>
        <div class="muted small">{{ [story.deepest.country, story.deepest.network].filter(Boolean).join(' · ') || '—' }}</div>
        <DepthMeter :depth="story.deepest.capability" :tier="story.deepest.depth" size="lg" :color="moodColor" />
        <div class="small reason">{{ story.deepest.reasons[0] }}</div>
      </RouterLink>
    </section>

    <div class="grid cols-4 kpis">
      <RouterLink class="card kpi" :to="{ path: '/actors', query: { class: 'rogue_agent' } }">
        <span class="k-label"><span class="swatch" style="background: var(--c-rogue)"></span>Rogue agents</span>
        <span class="k-n" :class="{ hot: (actors.summary.rogue_agent ?? 0) > 0 }">{{ fmtNum(actors.summary.rogue_agent ?? 0) }}</span>
        <span class="k-hint">used a planted credential</span>
      </RouterLink>
      <RouterLink class="card kpi" :to="{ path: '/actors', query: { class: 'ai_agent' } }">
        <span class="k-label"><span class="swatch" style="background: var(--c-agent)"></span>AI agents</span>
        <span class="k-n">{{ fmtNum(actors.summary.ai_agent ?? 0) }}</span>
        <span class="k-hint">explored, used no bait</span>
      </RouterLink>
      <RouterLink class="card kpi" to="/incidents">
        <span class="k-label"><span class="swatch" style="background: var(--serious)"></span>Incidents</span>
        <span class="k-n">{{ fmtNum((sev['critical'] ?? 0) + (sev['high'] ?? 0) + (sev['medium'] ?? 0)) }}</span>
        <span class="k-hint">{{ sev['critical'] ?? 0 }} critical · {{ sev['high'] ?? 0 }} high · {{ fmtNum(data.totals.canary_uses) }} canary uses</span>
      </RouterLink>
      <RouterLink class="card kpi" to="/actors">
        <span class="k-label"><span class="swatch" style="background: var(--text-muted)"></span>Visitors</span>
        <span class="k-n">{{ fmtNum(data.totals.sources) }}</span>
        <span class="k-hint">{{ fmtNum(data.totals.requests) }} requests · {{ fmtNum(data.totals.fingerprints) }} TLS fingerprints</span>
      </RouterLink>
    </div>

    <section class="card mixcard">
      <div class="row"><h2>Everyone who visited</h2><div class="spacer"></div><span class="muted small">classified by behavior, not by what they claim</span></div>
      <div class="mixbar" role="img" :aria-label="mix.map((c) => `${c.plural} ${c.n}`).join(', ')">
        <RouterLink v-for="c in mix.filter((c) => c.n > 0)" :key="c.key" :to="{ path: '/actors', query: { class: c.key } }"
          :style="{ width: `max(${c.pct}%, 6px)`, background: c.color }" :title="`${c.plural}: ${c.n}`" />
      </div>
      <div class="legend">
        <RouterLink v-for="c in mix" :key="c.key" :to="{ path: '/actors', query: { class: c.key } }" class="lg-item" :class="{ zero: !c.n }">
          <span class="swatch" :style="{ background: c.color }"></span>{{ c.plural }} <b>{{ fmtNum(c.n) }}</b>
        </RouterLink>
      </div>
    </section>

    <div class="grid cols-2">
      <section class="card">
        <h2>Requests per hour</h2>
        <EChart :option="timelineOption" label="Requests per hour" brushable @brush="drill" @themechange="themeTick++" />
        <p class="muted small hint">Drag across the chart to open the events in that window.</p>
        <p v-if="!data.timeline?.length" class="empty">No requests in this window.</p>
      </section>
      <section class="card">
        <div class="row"><h2>Traps sprung</h2><div class="spacer"></div>
          <button v-if="traps.idle" class="linkbtn small" @click="allTraps = !allTraps">{{ allTraps ? 'Only sprung traps' : `Show all ${data.funnel?.length ?? 0}` }}</button></div>
        <div v-if="traps.shown.length" class="bars">
          <div v-for="f in traps.shown" :key="f.name" class="bar-row" :class="{ zero: !f.sources }">
            <span class="bar-name"><span class="stage">{{ f.stage }}</span>{{ f.name }}</span>
            <span class="bar-track"><span class="bar-fill" :style="{ width: `${(100 * f.sources) / traps.max}%`, background: f.stage >= 3 ? 'var(--c-rogue)' : 'var(--serious)' }"></span></span>
            <span class="bar-n">{{ fmtNum(f.sources) }}</span>
          </div>
        </div>
        <p v-else class="empty">No trap has been sprung in this window.</p>
        <p v-if="traps.idle && !allTraps" class="muted small">{{ traps.idle }} other traps not reached. Stage 1–2: sample keys; 3–4: real secrets.</p>
      </section>
    </div>

    <div class="grid cols-2">
      <section class="card">
        <div class="row"><h2>Where they came from</h2><div class="spacer"></div><RouterLink to="/map" class="small">Open map →</RouterLink></div>
        <div v-if="countries.length" class="bars">
          <div v-for="c in countries" :key="c.cc" class="bar-row">
            <span class="bar-name"><span class="flag">{{ flag(c.cc) }}</span>{{ c.name }}<span v-if="c.rogue" class="pill rogue-pill">{{ c.rogue }} rogue</span></span>
            <span class="bar-track"><span class="bar-fill" :style="{ width: `${(100 * c.n) / countries[0]!.n}%`, background: 'var(--c-agent)' }"></span></span>
            <span class="bar-n">{{ c.n }}</span>
          </div>
        </div>
        <p v-else class="empty">No geolocated visitors. Mount the DB-IP database to see countries.</p>
        <p v-if="countries.length" class="muted small">IP geolocation by <a href="https://db-ip.com" target="_blank" rel="noopener">DB-IP</a></p>
      </section>
      <section class="card">
        <h2>Busiest sources</h2>
        <div class="table-wrap"><table>
          <thead><tr><th>Source</th><th>Events</th><th>Last seen</th></tr></thead>
          <tbody>
            <tr v-for="s in (data.top_sources ?? []).slice(0, 8)" :key="s.source">
              <td><Addr :ip="s.source" :cc="byIP.get(s.source)?.country_code" :country="byIP.get(s.source)?.country" />
                <div v-if="s.user_agent" class="muted small truncate ua-cell" :title="s.user_agent">{{ s.user_agent }}</div></td>
              <td><BarCell :value="s.events" :max="max(data.top_sources, (r) => r.events)" /></td>
              <td class="muted nowrap">{{ ago(s.last_seen) }}</td>
            </tr>
          </tbody>
        </table></div>
        <p v-if="!data.top_sources?.length" class="empty">No sources yet.</p>
      </section>
    </div>

    <div class="grid cols-2">
      <section class="card">
        <h2>Top TLS fingerprints (JA4)</h2>
        <div class="table-wrap"><table>
          <thead><tr><th>JA4 (hover for a sample user agent)</th><th>Sources</th><th class="num">Requests</th></tr></thead>
          <tbody>
            <tr v-for="f in data.top_fingerprints ?? []" :key="f.ja4">
              <td class="mono" :title="f.user_agent ? `e.g. ${f.user_agent}` : ''">{{ f.ja4 }}</td>
              <td><BarCell :value="f.sources" :max="max(data.top_fingerprints, (r) => r.sources)" /></td>
              <td class="num">{{ fmtNum(f.requests) }}</td>
            </tr>
          </tbody>
        </table></div>
        <p v-if="!data.top_fingerprints?.length" class="empty">No HTTPS requests with fingerprints yet.</p>
      </section>
      <section class="card">
        <h2>Top user agents</h2>
        <div class="table-wrap"><table>
          <thead><tr><th>User agent</th><th>Requests</th><th class="num">Sources</th></tr></thead>
          <tbody>
            <tr v-for="u in data.top_user_agents ?? []" :key="u.user_agent">
              <td class="truncate ua-cell" :title="u.user_agent">{{ u.user_agent || '(none)' }}</td>
              <td><BarCell :value="u.requests" :max="max(data.top_user_agents, (r) => r.requests)" /></td>
              <td class="num">{{ fmtNum(u.sources) }}</td>
            </tr>
          </tbody>
        </table></div>
      </section>
    </div>

    <section v-if="data.exploits?.length" class="card">
      <h2>Exploit attempts</h2>
      <p class="muted intro">Attacks on known vulnerabilities that honeypot modules recognized. "Exploits" sent a payload; "probes" only looked for a vulnerable target.</p>
      <div class="table-wrap"><table>
        <thead><tr><th>Attack</th><th>CVE</th><th>Exploits</th><th class="num">Probes</th><th class="num">Sources</th><th class="num">Last seen</th></tr></thead>
        <tbody>
          <tr v-for="x in data.exploits" :key="x.module + x.attack">
            <td>{{ x.attack || x.module }} <span class="muted">{{ x.module }}</span></td>
            <td class="mono">{{ (x.cves ?? []).join(', ') || '—' }}</td>
            <td><BarCell :value="x.attempts" :max="max(data.exploits, (r) => r.attempts)" /></td>
            <td class="num">{{ fmtNum(x.probes) }}</td>
            <td class="num">{{ fmtNum(x.sources) }}</td>
            <td class="num muted">{{ ago(x.last_seen) }}</td>
          </tr>
        </tbody>
      </table></div>
    </section>

    <section class="card">
      <h2>Top paths</h2>
      <div class="table-wrap"><table>
        <thead><tr><th>Surface</th><th>Path</th><th>Requests</th><th class="num">Sources</th></tr></thead>
        <tbody>
          <tr v-for="p in data.top_paths ?? []" :key="p.surface + p.path">
            <td class="muted">{{ p.surface || '(unknown host)' }}</td>
            <td class="mono truncate" :title="p.path">{{ p.path }}</td>
            <td><BarCell :value="p.requests" :max="max(data.top_paths, (r) => r.requests)" /></td>
            <td class="num">{{ fmtNum(p.sources) }}</td>
          </tr>
        </tbody>
      </table></div>
    </section>
  </template>
  <div v-else-if="!error" class="skeleton" aria-busy="true">
    <div class="card sk-hero"></div>
    <div class="grid cols-4"><div v-for="i in 4" :key="i" class="card sk-tile"></div></div>
  </div>
</template>

<style scoped>
.grid { margin-bottom: 16px; }
section.card { margin-bottom: 16px; }
.intro { font-size: 13px; margin: -4px 0 10px; }
.grid > section.card { margin-bottom: 0; }

.hero { display: grid; grid-template-columns: minmax(0, 1fr) 320px; gap: 24px; padding: 26px 28px; margin-bottom: 16px; position: relative; overflow: hidden;
  border-top: 4px solid var(--mood);
  background: linear-gradient(135deg, color-mix(in srgb, var(--mood) 7%, var(--surface-1)) 0%, var(--surface-1) 55%); }
.eyebrow { font-size: 11.5px; font-weight: 700; letter-spacing: 1.1px; text-transform: uppercase; color: var(--mood); }
.eyebrow.muted { color: var(--text-muted); }
.hero h1 { font-size: 30px; line-height: 1.2; margin: 8px 0 8px; letter-spacing: -0.5px; }
.detail { font-size: 15px; color: var(--text-secondary); margin: 0 0 18px; max-width: 620px; }
.ctas { gap: 8px; }
.cta { padding: 7px 14px; border-radius: 8px; border: 1px solid var(--border); background: var(--surface-1); color: var(--text-primary); font-weight: 500; font-size: 13.5px; }
.cta:hover { text-decoration: none; border-color: var(--text-muted); }
.cta.primary { background: var(--mood); border-color: var(--mood); color: #fff; }
.cta.primary:hover { filter: brightness(1.06); }
.deepest { display: grid; gap: 6px; align-content: start; padding: 16px 18px; border-radius: 10px; background: var(--surface-1); border: 1px solid var(--border); color: var(--text-primary); transition: box-shadow 0.15s, border-color 0.15s; }
.deepest:hover { text-decoration: none; box-shadow: var(--shadow-hover); border-color: var(--text-muted); }
.d-ip { font-size: 17px; font-weight: 600; }
.reason { color: var(--text-secondary); margin-top: 4px; }

.kpis { margin-bottom: 16px; }
.kpi { display: grid; gap: 4px; color: var(--text-primary); transition: box-shadow 0.15s, transform 0.15s; }
.kpi:hover { text-decoration: none; box-shadow: var(--shadow-hover); transform: translateY(-1px); }
.k-label { display: inline-flex; align-items: center; gap: 7px; color: var(--text-secondary); font-size: 13px; font-weight: 500; }
.swatch { width: 9px; height: 9px; border-radius: 3px; display: inline-block; flex: none; }
.k-n { font-size: 30px; font-weight: 700; font-variant-numeric: tabular-nums; letter-spacing: -0.5px; line-height: 1.15; }
.k-n.hot { color: var(--c-rogue); }
.k-hint { font-size: 12px; color: var(--text-muted); }

.mixbar { display: flex; height: 14px; border-radius: 7px; overflow: hidden; gap: 2px; margin: 4px 0 12px; background: var(--track); }
.mixbar a { display: block; transition: filter 0.15s; }
.mixbar a:hover { filter: brightness(1.12); }
.legend { display: flex; flex-wrap: wrap; gap: 6px 18px; }
.lg-item { display: inline-flex; align-items: center; gap: 7px; color: var(--text-secondary); font-size: 13px; }
.lg-item b { color: var(--text-primary); font-variant-numeric: tabular-nums; }
.lg-item.zero { opacity: 0.55; }
.lg-item:hover { text-decoration: none; color: var(--text-primary); }

.bars { display: grid; gap: 9px; margin-bottom: 10px; }
.bar-row { display: grid; grid-template-columns: minmax(150px, 44%) 1fr 36px; align-items: center; gap: 12px; font-size: 13.5px; }
.bar-row.zero { opacity: 0.5; }
.bar-name { display: flex; align-items: center; gap: 2px; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.stage { display: inline-grid; place-items: center; width: 18px; height: 18px; border-radius: 5px; background: var(--surface-2); color: var(--text-muted); font-size: 11px; font-weight: 600; margin-right: 8px; flex: none; }
.bar-track { height: 10px; border-radius: 5px; background: var(--track); overflow: hidden; }
.bar-fill { display: block; height: 100%; border-radius: 5px; min-width: 3px; transition: width 0.4s ease; }
.bar-n { text-align: right; font-weight: 600; font-variant-numeric: tabular-nums; }
.rogue-pill { margin-left: 8px; background: var(--rogue-soft); color: var(--c-rogue); font-weight: 600; font-size: 11px; }
.linkbtn { background: none; border: 0; color: var(--accent); padding: 0; }
.hint { margin: 6px 0 0; }
td .addr { font-size: 13px; }
.ua-cell { max-width: 280px; }

.sk-hero { height: 200px; margin-bottom: 16px; }
.sk-tile { height: 110px; }
.skeleton .card { background: linear-gradient(90deg, var(--surface-1), var(--surface-2), var(--surface-1)); background-size: 200% 100%; animation: shimmer 1.4s linear infinite; }
@keyframes shimmer { to { background-position: -200% 0; } }

@media (max-width: 1000px) { .hero { grid-template-columns: 1fr; } }
@media (max-width: 760px) { .hero { padding: 20px; } .hero h1 { font-size: 24px; } }
</style>
