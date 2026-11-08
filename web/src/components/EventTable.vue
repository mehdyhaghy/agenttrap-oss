<script setup lang="ts">
import { ref } from 'vue'
import type { EventRecord } from '../api'
import { fmtTime } from '../format'

defineProps<{ events: EventRecord[]; showSource?: boolean }>()
const open = ref<string | null>(null)

const kindLabel: Record<string, string> = {
  request: 'Request',
  auth: 'Credential',
  canary_exposed: 'Canary shown',
  canary_used: 'Canary used',
  tool_call: 'Tool / API call',
  form: 'Form',
  tls_hello: 'TLS hello',
}
function ja4(e: EventRecord): string {
  const v = e.detail?.['ja4']
  return typeof v === 'string' ? v : ''
}
</script>

<template>
  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>Time</th><th v-if="showSource">Source</th><th>Kind</th><th>Surface</th><th>Request</th>
          <th class="num">Status</th><th>Canary</th><th>JA4</th><th>User agent</th>
        </tr>
      </thead>
      <tbody>
        <template v-for="e in events" :key="e.id">
          <tr :class="{ canary: e.kind === 'canary_used', clickable: true }" @click="open = open === e.id ? null : e.id">
            <td class="muted nowrap">{{ fmtTime(e.time) }}</td>
            <td v-if="showSource" class="mono"><RouterLink :to="`/sources/${encodeURIComponent(e.source)}`" @click.stop>{{ e.source }}</RouterLink></td>
            <td class="nowrap"><strong v-if="e.kind === 'canary_used'">⚑ </strong>{{ kindLabel[e.kind] ?? e.kind }}</td>
            <td class="muted">{{ e.surface || '—' }}</td>
            <td class="mono truncate" :title="`${e.method ?? ''} ${e.path ?? ''}`">{{ e.method }} {{ e.path }}</td>
            <td class="num">{{ e.status || '' }}</td>
            <td class="mono">{{ e.canary_slot || '' }}</td>
            <td class="mono nowrap">{{ ja4(e) }}</td>
            <td class="truncate muted" :title="e.user_agent">{{ e.user_agent }}</td>
          </tr>
          <tr v-if="open === e.id" class="detail">
            <td :colspan="showSource ? 9 : 8"><pre class="mono">{{ JSON.stringify(e, null, 2) }}</pre></td>
          </tr>
        </template>
      </tbody>
    </table>
  </div>
  <p v-if="!events.length" class="empty">No events.</p>
</template>

<style scoped>
.nowrap { white-space: nowrap; }
tr.clickable { cursor: pointer; }
tr.clickable:hover td { background: var(--surface-2); }
tr.canary td { background: color-mix(in srgb, var(--critical) 10%, transparent); }
tr.detail td { background: var(--surface-2); }
pre { margin: 0; white-space: pre-wrap; word-break: break-all; max-height: 360px; overflow: auto; }
</style>
