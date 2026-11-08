<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import type { EventRecord } from '../api'
import { fmtTime } from '../format'

const props = defineProps<{ events: EventRecord[] }>()

type Cat = 'recon' | 'cred' | 'used' | 'esc' | 'exfil'
interface Step { time: string; icon: string; label: string; detail?: string; cat: Cat }

const catColor: Record<Cat, string> = {
  recon: 'var(--text-muted)',
  cred: 'var(--accent)',
  used: 'var(--accent)',
  esc: '#f59e0b',
  exfil: 'var(--critical)',
}

function slotLabel(slot?: string): string {
  const m: Record<string, string> = {
    provider_key_vllm: 'the vLLM provider key',
    repo_vllm_key: 'the vLLM provider key (from GitHub)',
    docs_sample_key: 'a sample API key',
    repo_sample_key: 'a sample API key (from GitHub)',
    pg_app_password: 'the database password',
    ssh_deploy_password: 'the deploy SSH password',
    redis_session_token: 'a cache session token',
    aws_access_key_id: 'an AWS access key',
    aws_sts_access_key_id: 'instance-role credentials',
    kube_token: 'the Kubernetes token',
    hf_token: 'the Hugging Face token',
    oauth_access_token: 'an OAuth access token',
    oauth_client_secret: 'a service-account secret',
    service_account_secret: 'a service-account secret',
  }
  return (slot && m[slot]) || slot || 'a credential'
}
const s = (v: unknown): string => (typeof v === 'string' ? v : '')
const clip = (v: unknown, n = 70): string => { const t = s(v); return t.length > n ? t.slice(0, n) + '…' : t }

function opStep(op: string, d: Record<string, unknown>): Omit<Step, 'time'> | null {
  if (op.startsWith('cloud_')) return { icon: '☁', cat: 'used', label: `AWS ${s(d['action']) || op.slice(6)}`, detail: clip(d['secret_id'] || d['bucket'] || d['name']) }
  if (op.startsWith('kube_')) return { icon: '⬡', cat: s(d['resource']) === 'secrets' ? 'esc' : 'used', label: `Kubernetes ${op.slice(5)} ${s(d['resource'])}`, detail: clip(d['namespace']) }
  switch (op) {
    case 'ssh_command': case 'ssh_exec': return { icon: '$', cat: 'recon', label: `Ran: ${clip(d['command'], 90)}` }
    case 'ssh_fetch': return { icon: '↗', cat: 'recon', label: `Fetched ${clip(d['url'])} from the node` }
    case 'imds': return { icon: '☁', cat: 'esc', label: 'Queried the instance metadata service', detail: clip(d['path']) }
    case 'egress': return { icon: '↗', cat: (d['exfil_slots'] as unknown[] | undefined)?.length ? 'exfil' : 'recon', label: `Outbound to ${s(d['host'])}`, detail: `${s(d['action'])}` }
    case 'memory_read': return { icon: '🧠', cat: d['has_secret'] ? 'used' : 'recon', label: `Read team memory ${s(d['memory_id'])}`, detail: clip(d['owner']) }
    case 'memory_write': return { icon: '🧠', cat: 'esc', label: 'Wrote to shared memory (possible poisoning)' }
    case 'memory_search': return { icon: '🔎', cat: 'recon', label: `Searched memory "${clip(d['query'], 50)}"` }
    case 'kb_get': return { icon: '▤', cat: d['has_secret'] ? 'used' : 'recon', label: `Retrieved document ${s(d['doc_id'])}` }
    case 'kb_search': return { icon: '🔎', cat: 'recon', label: `Searched the knowledge base "${clip(d['query'], 50)}"` }
    case 'chat': case 'embeddings': return { icon: '◇', cat: 'recon', label: `Model API call (${op})` }
    case 'agent_register': return { icon: '◈', cat: 'recon', label: `Registered as ${clip(d['agent'], 50) || 'an agent'}` }
    case 'trial_key': return { icon: '🔑', cat: 'recon', label: 'Requested a trial API key' }
    case 'pg_query': return { icon: '▤', cat: 'used', label: `SQL: ${clip(d['query'], 90)}` }
    case 'redis_command': case 'redis_config_set': case 'redis_replicaof': case 'redis_module':
      return { icon: '▦', cat: op === 'redis_command' ? 'used' : 'esc', label: `Cache: ${clip(d['command'], 80)}` }
    case 'ssh_forward': return { icon: '⇄', cat: 'esc', label: 'Tried to forward a port through the node' }
    default: return op ? { icon: '·', cat: 'recon', label: op.replace(/_/g, ' ') } : null
  }
}

function stepFor(e: EventRecord): Step | null {
  const d = (e.detail ?? {}) as Record<string, unknown>
  const base = { time: e.time }
  switch (e.kind) {
    case 'connect': return { ...base, icon: '⇢', cat: 'recon', label: `Connected (${e.surface || e.protocol})`, detail: clip(d['client_version']) }
    case 'auth': return { ...base, icon: '🔑', cat: 'cred', label: `Presented a credential${d['where'] ? ` at ${s(d['where'])}` : ''}` }
    case 'canary_exposed': return { ...base, icon: '◆', cat: 'cred', label: `Was shown ${slotLabel(e.canary_slot)}${d['via'] ? ` (via ${s(d['via'])})` : ''}` }
    case 'canary_used':
      if (d['exfil'] === true) return { ...base, icon: '⚑', cat: 'exfil', label: `Exfiltrated ${slotLabel(e.canary_slot)} → ${s(d['destination'])}` }
      return { ...base, icon: '✸', cat: 'used', label: `Used ${slotLabel(e.canary_slot)}` }
    case 'tool_call': { const st = opStep(s(d['op']), d); return st ? { ...base, ...st } : null }
    case 'form': return { ...base, icon: '▤', cat: 'recon', label: `Submitted a form (${s(d['form']) || '?'})` }
    default: return null
  }
}

// Oldest first: the story unfolds forward in time. Cap for readability.
const steps = computed<Step[]>(() => {
  const out: Step[] = []
  for (let i = props.events.length - 1; i >= 0; i--) {
    const ev = props.events[i]
    if (!ev) continue
    const st = stepFor(ev)
    if (st) out.push(st)
  }
  return out.slice(0, 60)
})

const clock = (t: string): string => new Date(t).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false })

const rel = (t: string): string => {
  if (!steps.value.length) return ''
  const start = new Date(steps.value[0]?.time ?? t).getTime()
  const ms = new Date(t).getTime() - start
  if (ms < 1000) return '+0s'
  const sTot = Math.round(ms / 1000)
  if (sTot < 60) return `+${sTot}s`
  const m = Math.floor(sTot / 60)
  if (m < 60) return `+${m}m${sTot % 60 ? ` ${sTot % 60}s` : ''}`
  const h = Math.floor(m / 60)
  return `+${h}h ${m % 60}m`
}

// Animated reveal: steps appear one at a time; Replay restarts.
const visible = ref(0)
let timer: number | undefined
function play(): void {
  window.clearInterval(timer)
  visible.value = 0
  const n = steps.value.length
  if (!n) return
  const gap = Math.max(120, Math.min(400, Math.round(4000 / n)))
  timer = window.setInterval(() => {
    visible.value++
    if (visible.value >= n) window.clearInterval(timer)
  }, gap)
}
watch(steps, play, { immediate: true })
onBeforeUnmount(() => window.clearInterval(timer))
</script>

<template>
  <div v-if="steps.length" class="card steps">
    <div class="row head">
      <h2>What it did <span class="muted count">{{ steps.length }} steps · started {{ fmtTime(steps[0]!.time) }}</span></h2>
      <div class="spacer"></div>
      <button type="button" class="replay" @click="play"><span aria-hidden="true">▶</span> Replay</button>
    </div>
    <ol class="tl" :style="{ '--shown': visible }">
      <li v-for="(st, i) in steps" :key="i" class="step" :class="{ show: i < visible, latest: i === visible - 1 }">
        <div class="when"><span class="abs">{{ clock(st.time) }}</span><span class="delta muted">{{ rel(st.time) }}</span></div>
        <svg class="dot" viewBox="0 0 24 24" width="24" height="24" aria-hidden="true">
          <circle class="ring" cx="12" cy="12" r="9" :style="{ stroke: catColor[st.cat] }" />
          <circle cx="12" cy="12" r="4.5" :style="{ fill: catColor[st.cat] }" />
        </svg>
        <div class="body">
          <span class="ico" :style="{ color: catColor[st.cat] }">{{ st.icon }}</span>
          <span class="label">{{ st.label }}</span>
          <span v-if="st.detail" class="detail muted mono">{{ st.detail }}</span>
        </div>
      </li>
    </ol>
  </div>
</template>

<style scoped>
.steps { margin-bottom: 16px; }
.head { align-items: center; }
.head h2 { margin: 0; }
.spacer { flex: 1; }
.tl { list-style: none; margin: 8px 0 0; padding: 0; position: relative; }
/* The rail the dots sit on. */
.tl::before { content: ''; position: absolute; left: 96px; top: 6px; bottom: 6px; width: 2px; background: var(--border); }
.step { display: grid; grid-template-columns: 84px 24px 1fr; align-items: start; gap: 8px; padding: 5px 0;
  opacity: 0; transform: translateY(8px); transition: opacity 0.35s ease, transform 0.35s ease; }
.step.show { opacity: 1; transform: none; }
.when { text-align: right; font-variant-numeric: tabular-nums; }
.when .abs { display: block; font-size: 12.5px; font-family: var(--mono); }
.when .delta { display: block; font-size: 11px; }
.dot { flex: none; }
.dot .ring { fill: none; stroke-width: 2; opacity: 0.55; }
.step.latest .dot .ring { animation: pulse 1s ease-out; }
@keyframes pulse { from { transform: scale(0.6); transform-origin: center; opacity: 1; } to { transform: scale(1); opacity: 0.55; } }
.body { padding-top: 1px; }
.ico { margin-right: 6px; }
.label { font-weight: 500; }
.count { font-weight: 400; margin-left: 6px; }
.detail { display: block; font-size: 11.5px; margin-top: 1px; word-break: break-all; }
@media (max-width: 640px) { .tl::before { left: 84px; } .step { grid-template-columns: 72px 24px 1fr; } }
</style>
