<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { api, type Research } from '../api'
import { refreshTick, windowHours } from '../state'
import { ago, fmtTime } from '../format'
import StatTile from '../components/StatTile.vue'
import SeverityBadge from '../components/SeverityBadge.vue'
import ClassBadge from '../components/ClassBadge.vue'
import BarCell from '../components/BarCell.vue'

const data = ref<Research | null>(null)
const error = ref('')

async function load(): Promise<void> {
  try {
    data.value = await api.research(windowHours.value)
    error.value = ''
  } catch (e) {
    error.value = (e as Error).message
  }
}
watch([windowHours, refreshTick], load, { immediate: true })

const campaigns = computed(() => data.value?.campaigns ?? [])
const clusters = computed(() => data.value?.clusters ?? [])
const d = computed(() => data.value?.deception)
const lures = computed(() => d.value?.lures ?? [])
const depth = computed(() => [1, 2, 3, 4].map((s) => ({ stage: s, n: d.value?.depth?.[String(s)] ?? 0 })))
const depthMax = computed(() => Math.max(0, ...depth.value.map((x) => x.n)))
const scopes = computed(() => Object.entries(d.value?.honey_scopes ?? {}).sort((a, b) => b[1] - a[1]))
const hintRate = computed(() => {
  const shown = d.value?.hints_shown ?? 0
  return shown ? `${d.value?.hints_followed ?? 0} of ${shown} followed` : 'none shown yet'
})
const pct = (r: number): string => `${Math.round(r * 100)}%`
const stageNames: Record<number, string> = { 1: 'Key issued', 2: 'Key used', 3: 'Provider key or service account revealed', 4: 'Reused (definitive)' }
</script>

<template>
  <h1>Campaigns and deception</h1>
  <p class="muted note">
    Campaigns join addresses that are one operation: shared keys, sessions, declared identities, or the same behavior with the same client software.
    Clusters group clients that behave alike, which alone is not proof of one operator.
  </p>
  <p v-if="error" class="error">{{ error }}</p>

  <div class="grid cols-4 tiles">
    <StatTile label="Campaigns" :value="String(campaigns.length)" :hint="`${campaigns.filter((c) => c.severity === 'critical').length} critical`" />
    <StatTile label="Behavioral clusters" :value="String(clusters.length)" hint="families of look-alike clients" />
    <StatTile label="Decoy ops agent" :value="String(d?.decoy_agent ?? 0)" hint="addresses that delegated to it" />
    <StatTile label="Depth hints" :value="String(d?.hints_shown ?? 0)" :hint="hintRate" />
  </div>

  <div class="card section">
    <h2>Campaigns ({{ campaigns.length }})</h2>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Severity</th><th>Campaign</th><th>Addresses</th><th>Why joined</th><th>Software</th><th>First seen</th><th>Last seen</th></tr></thead>
        <tbody>
          <tr v-for="c in campaigns" :key="c.id">
            <td><SeverityBadge :severity="c.severity" /></td>
            <td><span class="mono">{{ c.id }}</span><div class="muted small">{{ c.summary }}</div></td>
            <td class="mono iplist">
              <RouterLink v-for="m in c.members.slice(0, 8)" :key="m" :to="`/sources/${encodeURIComponent(m)}`" class="member">{{ m }}</RouterLink>
              <span v-if="c.members.length > 8" class="muted">+{{ c.members.length - 8 }} more</span>
            </td>
            <td>
              <details>
                <summary>{{ c.joins.length }} link(s)</summary>
                <ul><li v-for="j in c.joins" :key="j">{{ j }}</li></ul>
              </details>
            </td>
            <td>{{ (c.frameworks ?? []).join(', ') || '—' }}</td>
            <td class="muted">{{ fmtTime(c.first_seen) }}</td>
            <td class="muted">{{ ago(c.last_seen) }}</td>
          </tr>
        </tbody>
      </table>
      <p v-if="!campaigns.length" class="empty">No campaigns in this window.</p>
    </div>
  </div>

  <div class="grid cols-2 section">
    <div class="card">
      <h2>Chain depth</h2>
      <table>
        <thead><tr><th>Stage</th><th>Addresses</th></tr></thead>
        <tbody>
          <tr v-for="s in depth" :key="s.stage">
            <td>{{ s.stage }} · {{ stageNames[s.stage] }}</td>
            <td><BarCell :value="s.n" :max="depthMax" /></td>
          </tr>
        </tbody>
      </table>
    </div>
    <div class="card">
      <h2>Honey scopes requested</h2>
      <p v-if="!scopes.length" class="muted">None requested.</p>
      <ul v-else><li v-for="[scope, n] in scopes" :key="scope"><span class="mono">{{ scope }}</span> · {{ n }} address(es)</li></ul>
      <p class="muted small">Admin-only honey tools called by {{ d?.honey_tools ?? 0 }} address(es).</p>
    </div>
  </div>

  <div class="card section">
    <h2>Lure wordings</h2>
    <p class="muted small">Each address sees one wording of each honey tool. Rate is the share of addresses that saw it and then called the tool.</p>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Tool</th><th>Wording</th><th class="num">Saw</th><th class="num">Called</th><th class="num">Rate</th></tr></thead>
        <tbody>
          <tr v-for="l in lures" :key="l.family + l.variant">
            <td class="mono">{{ l.family }} <span class="muted">{{ l.variant }}</span></td>
            <td class="wording">{{ l.text }}</td>
            <td class="num">{{ l.shown }}</td>
            <td class="num">{{ l.called }}</td>
            <td class="num">{{ l.shown ? pct(l.rate) : '—' }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>

  <div class="card section">
    <h2>Behavioral clusters ({{ clusters.length }})</h2>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Cluster</th><th>Classes</th><th class="num">Members</th><th class="num">Cohesion</th><th>Shared behavior</th></tr></thead>
        <tbody>
          <tr v-for="c in clusters" :key="c.id">
            <td class="mono">{{ c.id }}</td>
            <td><ClassBadge v-for="cl in c.classes" :key="cl" :cls="cl" class="cls" /></td>
            <td class="num">
              <details>
                <summary>{{ c.members.length }}</summary>
                <RouterLink v-for="m in c.members" :key="m" :to="`/sources/${encodeURIComponent(m)}`" class="mono member block">{{ m }}</RouterLink>
              </details>
            </td>
            <td class="num">{{ c.cohesion.toFixed(2) }}</td>
            <td class="signature"><span v-for="t in c.signature" :key="t" class="token mono">{{ t }}</span></td>
          </tr>
        </tbody>
      </table>
      <p v-if="!clusters.length" class="empty">No clusters in this window.</p>
    </div>
  </div>
</template>

<style scoped>
h1 { margin: 0; }
.note { margin: 6px 0 16px; max-width: 900px; }
.tiles, .section { margin-bottom: 16px; }
.small { font-size: 12px; }
.member { margin-right: 10px; }
.block { display: block; margin: 2px 0; }
.sub { margin-top: 18px; }
ul { margin: 6px 0 0; padding-left: 18px; }
details summary { cursor: pointer; color: var(--text-secondary); }
.wording { min-width: 260px; }
.cls { margin-right: 10px; }
.signature { max-width: 560px; }
.token { display: inline-block; margin: 0 6px 4px 0; padding: 1px 6px; border-radius: 4px; background: var(--surface-2); border: 1px solid var(--border); font-size: 11.5px; word-break: break-all; }
@media (max-width: 900px) { .cols-4 { grid-template-columns: repeat(2, minmax(0, 1fr)); } .cols-2 { grid-template-columns: 1fr; } }
</style>
