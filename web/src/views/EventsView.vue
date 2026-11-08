<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api, type EventRecord } from '../api'
import { refreshTick } from '../state'
import { fmtTime } from '../format'
import EventTable from '../components/EventTable.vue'

const route = useRoute()
const router = useRouter()
const events = ref<EventRecord[]>([])
const kind = ref('')
const surface = ref('')
const live = ref(true)
const error = ref('')
let timer: number | undefined

// A ?from=/&to= range (Unix seconds) comes from brushing the Overview timeline.
const from = computed(() => Number(route.query['from']) || undefined)
const to = computed(() => Number(route.query['to']) || undefined)
const hasRange = computed(() => from.value !== undefined && to.value !== undefined)

async function load(): Promise<void> {
  try {
    events.value =
      (await api.events({ kind: kind.value, surface: surface.value, from: from.value, to: to.value, limit: hasRange.value ? 1000 : 300 })) ?? []
    error.value = ''
  } catch (e) {
    error.value = (e as Error).message
  }
}
watch([kind, surface, from, to, refreshTick], load, { immediate: true })
onMounted(() => {
  timer = window.setInterval(() => {
    if (live.value && !hasRange.value && document.visibilityState === 'visible') void load()
  }, 5000)
})
onBeforeUnmount(() => window.clearInterval(timer))

function clearRange(): void {
  const q: Record<string, string> = {}
  if (kind.value) q['kind'] = kind.value
  if (surface.value) q['surface'] = surface.value
  void router.push({ path: '/events', query: q })
}
</script>

<template>
  <div class="row head">
    <h1>{{ hasRange ? 'Events' : 'Live events' }}</h1>
    <div class="spacer"></div>
    <select v-model="kind" aria-label="Kind">
      <option value="">All kinds</option>
      <option value="request">Requests</option>
      <option value="canary_used">Canary used</option>
      <option value="canary_exposed">Canary shown</option>
      <option value="auth">Credentials</option>
      <option value="tool_call">Tool / API calls</option>
      <option value="form">Forms</option>
      <option value="connect">Connections</option>
      <option value="tls_hello">TLS hellos</option>
    </select>
    <select v-model="surface" aria-label="Surface">
      <option value="">All surfaces</option>
      <option v-for="s in ['www', 'docs', 'api', 'console', 'mcp', 'status', 'vllm', 'aws', 'k8s', 'ssh', 'redis', 'postgres']" :key="s" :value="s">{{ s }}</option>
    </select>
    <label v-if="!hasRange" class="row muted"><input type="checkbox" v-model="live" /> Live (5s)</label>
  </div>
  <p v-if="hasRange" class="range">
    Window <b>{{ fmtTime(new Date((from as number) * 1000).toISOString()) }}</b> to
    <b>{{ fmtTime(new Date((to as number) * 1000).toISOString()) }}</b> · {{ events.length }} event(s)
    <button type="button" @click="clearRange">Clear window</button>
  </p>
  <p v-if="error" class="error">{{ error }}</p>
  <div class="card"><EventTable :events="events" show-source /></div>
</template>

<style scoped>
.head { margin-bottom: 16px; }
.head h1 { margin: 0; }
.range { display: flex; align-items: center; gap: 10px; margin: -6px 0 14px; padding: 8px 12px; background: var(--surface-2); border: 1px solid var(--border); border-radius: 8px; }
.range button { margin-left: auto; }
</style>
