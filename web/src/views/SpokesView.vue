<script setup lang="ts">
import { ref, watch } from 'vue'
import { api, type Spoke } from '../api'
import { refreshTick } from '../state'
import { ago, fmtTime } from '../format'

const spokes = ref<Spoke[]>([])
const error = ref('')
async function load(): Promise<void> {
  try {
    spokes.value = (await api.spokes()) ?? []
    error.value = ''
  } catch (e) {
    error.value = (e as Error).message
  }
}
watch(refreshTick, load, { immediate: true })

function health(s: Spoke): { label: string; icon: string; color: string } {
  if (s.revoked) return { label: 'Revoked', icon: '■', color: 'var(--text-muted)' }
  if (!s.last_seen) return { label: 'Never connected', icon: '▲', color: 'var(--warning)' }
  const age = (Date.now() - new Date(s.last_seen).getTime()) / 1000
  return age < 120
    ? { label: 'Connected', icon: '●', color: 'var(--good)' }
    : { label: 'Stale', icon: '▲', color: 'var(--serious)' }
}
</script>

<template>
  <h1>Spokes</h1>
  <p v-if="error" class="error">{{ error }}</p>
  <div class="card table-wrap">
    <table>
      <thead><tr><th>Spoke</th><th>Status</th><th>Last seen</th><th>Enrolled</th></tr></thead>
      <tbody>
        <tr v-for="s in spokes" :key="s.id">
          <td class="mono">{{ s.id }}</td>
          <td><span :style="{ color: health(s).color }" aria-hidden="true">{{ health(s).icon }}</span> {{ health(s).label }}</td>
          <td class="muted">{{ s.last_seen ? ago(s.last_seen) : '—' }}</td>
          <td class="muted">{{ fmtTime(s.created_at) }}</td>
        </tr>
      </tbody>
    </table>
  </div>
</template>
