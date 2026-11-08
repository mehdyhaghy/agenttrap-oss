<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { api, type Incident } from '../api'
import { refreshTick } from '../state'
import { ago, fmtTime } from '../format'
import SeverityBadge from '../components/SeverityBadge.vue'

const rows = ref<Incident[]>([])
const error = ref('')
const showExposures = ref(false)

async function load(): Promise<void> {
  try {
    rows.value = (await api.incidents()) ?? []
    error.value = ''
  } catch (e) {
    error.value = (e as Error).message
  }
}
watch(refreshTick, load, { immediate: true })

const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 }
const visible = computed(() =>
  rows.value
    .filter((i) => showExposures.value || i.severity !== 'low')
    .sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9) || b.last_seen.localeCompare(a.last_seen)),
)
const exposures = computed(() => rows.value.filter((i) => i.severity === 'low').length)
</script>

<template>
  <div class="row head">
    <h1>Incidents</h1>
    <div class="spacer"></div>
    <label class="row muted"><input type="checkbox" v-model="showExposures" /> Show exposure-only ({{ exposures }})</label>
  </div>
  <p class="muted note">An exposure means a source only saw a canary (for example the docs page). An incident starts when a canary is used.</p>
  <p v-if="error" class="error">{{ error }}</p>
  <div class="card table-wrap">
    <table>
      <thead>
        <tr><th>Severity</th><th>Source</th><th>Stages reached</th><th class="num">Score</th><th>Flags</th><th>First seen</th><th>Last seen</th></tr>
      </thead>
      <tbody>
        <tr v-for="i in visible" :key="i.id">
          <td><SeverityBadge :severity="i.severity" /></td>
          <td class="mono"><RouterLink :to="`/sources/${encodeURIComponent(i.source)}`">{{ i.source }}</RouterLink></td>
          <td>
            <span v-for="s in [1, 2, 3, 4]" :key="s" class="stage" :class="{ on: i.stages.includes(s) }" :title="`Stage ${s}`">{{ s }}</span>
          </td>
          <td class="num">{{ i.score }}</td>
          <td>
            <span v-if="i.out_of_band" class="flag" title="Used a canary it was never shown here">Out of band</span>
            <span v-if="i.cross_spoke" class="flag" title="Canary from another spoke">Cross-spoke</span>
            <span v-if="i.relayed" class="flag" title="Key revealed to one address and used from another">Relayed</span>
          </td>
          <td class="muted">{{ fmtTime(i.first_seen) }}</td>
          <td class="muted">{{ ago(i.last_seen) }}</td>
        </tr>
      </tbody>
    </table>
    <p v-if="!visible.length" class="empty">No incidents{{ showExposures ? '' : ' (exposures hidden)' }}.</p>
  </div>
</template>

<style scoped>
.head h1 { margin: 0; }
.note { margin: 6px 0 16px; }
.stage { display: inline-grid; place-items: center; width: 22px; height: 22px; margin-right: 4px; border-radius: 4px; font-size: 12px; border: 1px solid var(--border); color: var(--text-muted); }
.stage.on { background: var(--series-1); border-color: var(--series-1); color: #fff; font-weight: 600; }
.flag { display: inline-block; margin-right: 6px; padding: 1px 7px; border-radius: 10px; font-size: 12px; background: var(--surface-2); border: 1px solid var(--border); }
</style>
