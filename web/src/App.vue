<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { api, setToken, getToken, UnauthorizedError, type IngestHealth, type Persona } from './api'
import { authed, lastLoaded, pulse, refreshTick, windowHours } from './state'
import { fmtTime } from './format'

const tokenInput = ref('')
// Events not reaching the hub make every view undercount, so it is flagged
// on every page, not just the overview.
const health = ref<IngestHealth | null>(null)
// Failing to ask is not an ingestion problem: the tunnel dropped or the hub is
// restarting (as on every deploy). One miss keeps the last answer; only a
// second in a row (~30 s) shows a separate "can't reach the hub" notice.
const healthMisses = ref(0)
const unreachableSince = ref<number | null>(null)
async function checkHealth(): Promise<void> {
  if (!authed.value) return
  try {
    health.value = await api.health()
    healthMisses.value = 0
    unreachableSince.value = null
  } catch (e) {
    if (e instanceof UnauthorizedError) return
    if (healthMisses.value === 0) unreachableSince.value = Date.now()
    healthMisses.value++
  }
}
watch([authed, refreshTick], checkHealth, { immediate: true })
const ingestBroken = computed(() => (health.value?.problems.length ?? 0) > 0)
const hubUnreachable = computed(() => healthMisses.value >= 2)
// Built from the structured fields so times show in the viewer's zone; the
// hub's own sentences (UTC) are the fallback when it could not be asked.
const ingestProblems = computed((): string[] => {
  const h = health.value
  if (!h) return []
  const lines = h.spokes.flatMap((s) => {
    const err = s.last_error ? ` (${s.last_error})` : ''
    switch (s.status) {
      case 'failing':
        return [`Spoke ${s.spoke_id}: events are not being stored — ${s.failures} shipments refused since ${s.failing_since ? fmtTime(s.failing_since) : '?'}${err}`]
      case 'silent':
        return [`Spoke ${s.spoke_id}: no contact since ${s.last_contact ? fmtTime(s.last_contact) : 'the hub started'} — spoke down or cannot reach the hub`]
      case 'backlog':
        return [`Spoke ${s.spoke_id}: ${s.queue_depth} event batches waiting to be shipped`]
      case 'rejected':
        return [`Spoke ${s.spoke_id}: ${s.rejected_24h} batch(es) refused as unstorable in the last 24h and set aside on the spoke${err}`]
      default:
        return []
    }
  })
  return lines.length ? lines : h.problems
})
const loginError = ref('')
const persona = ref<Persona | null>(null)
const checking = ref(true)
const now = ref(Date.now())
let timer: number | undefined
let clock: number | undefined

async function verify(): Promise<void> {
  try {
    persona.value = await api.persona()
    authed.value = true
    loginError.value = ''
  } catch (e) {
    authed.value = false
    if (e instanceof UnauthorizedError) {
      if (getToken()) loginError.value = 'That token was not accepted.'
      setToken('')
    } else {
      loginError.value = `Hub unreachable: ${(e as Error).message}`
    }
  } finally {
    checking.value = false
  }
}

async function login(): Promise<void> {
  setToken(tokenInput.value.trim())
  tokenInput.value = ''
  await verify()
}

function logout(): void {
  setToken('')
  authed.value = false
  persona.value = null
}

onMounted(() => {
  if (getToken()) void verify()
  else checking.value = false
  timer = window.setInterval(() => {
    if (authed.value && document.visibilityState === 'visible') refreshTick.value++
  }, 30_000)
  clock = window.setInterval(() => { now.value = Date.now() }, 1_000)
})
onBeforeUnmount(() => {
  window.clearInterval(timer)
  window.clearInterval(clock)
})

const updated = computed(() => {
  if (lastLoaded.value === null) return 'connecting…'
  const s = Math.max(0, Math.round((now.value - lastLoaded.value) / 1000))
  return s < 5 ? 'updated just now' : s < 60 ? `updated ${s}s ago` : `updated ${Math.floor(s / 60)}m ago`
})
// Stale when two refresh cycles were missed (hub unreachable or tab asleep).
const stale = computed(() => lastLoaded.value !== null && now.value - lastLoaded.value > 75_000)

// Minimal line icons, drawn on a 20-unit grid.
const NAV = [
  { to: '/', label: 'Overview', exact: true, icon: 'M3 3h6v6H3zM11 3h6v6h-6zM3 11h6v6H3zM11 11h6v6h-6z' },
  { to: '/actors', label: 'Actors', badge: 'rogue', icon: 'M7 9a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM1.5 17c0-3 2.5-5 5.5-5s5.5 2 5.5 5M14 9a2.5 2.5 0 1 0 0-5M15 12c2.2.4 3.5 2.2 3.5 5' },
  { to: '/incidents', label: 'Incidents', badge: 'urgent', icon: 'M10 2.5 18.5 17h-17zM10 8v4M10 14.5v.01' },
  { to: '/research', label: 'Campaigns', icon: 'M10 2 18 6l-8 4-8-4zM2 10l8 4 8-4M2 14l8 4 8-4' },
  { to: '/map', label: 'Attack map', icon: 'M10 18a8 8 0 1 0 0-16 8 8 0 0 0 0 16zM2 10h16M10 2c2.2 2.2 3.2 5 3.2 8s-1 5.8-3.2 8c-2.2-2.2-3.2-5-3.2-8s1-5.8 3.2-8z' },
  { to: '/events', label: 'Live events', icon: 'M1.5 10h3.5l2.5-6 5 12 2.5-6h3.5' },
  { to: '/spokes', label: 'Spokes', icon: 'M3 3h14v5H3zM3 12h14v5H3zM6 5.5v.01M6 14.5v.01' },
  { to: '/settings', label: 'Settings', icon: 'M10 12.5a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5zM10 1.5v2.5M10 16v2.5M1.5 10H4M16 10h2.5M4 4l1.8 1.8M14.2 14.2 16 16M4 16l1.8-1.8M14.2 5.8 16 4' },
] as const
function badge(kind?: string): number {
  if (kind === 'rogue') return pulse.value.rogue ?? 0
  if (kind === 'urgent') return pulse.value.urgent ?? 0
  return 0
}
</script>

<template>
  <div v-if="checking" class="center muted">Loading…</div>

  <div v-else-if="!authed" class="center login-bg">
    <form class="card login" @submit.prevent="login">
      <div class="mark big" aria-hidden="true"><span></span></div>
      <h1>AgentTrap</h1>
      <p class="muted">See which AI agents took the bait. Sign in with the hub admin token (<span class="mono">secrets/admin_token</span> on the server).</p>
      <input v-model="tokenInput" type="password" autocomplete="off" placeholder="Admin token" aria-label="Admin token" autofocus />
      <button class="primary" type="submit" :disabled="!tokenInput">Sign in</button>
      <p v-if="loginError" class="error">{{ loginError }}</p>
    </form>
  </div>

  <div v-else class="shell">
    <aside>
      <div class="brand">
        <div class="mark" aria-hidden="true"><span></span></div>
        <div>
          <div class="name">AgentTrap</div>
          <div v-if="persona" class="persona">{{ persona.company }} · {{ persona.domain }}</div>
        </div>
      </div>
      <nav>
        <RouterLink v-for="n in NAV" :key="n.to" :to="n.to" :exact-active-class="'exact' in n ? 'active' : ''" :active-class="'exact' in n ? '' : 'active'">
          <svg viewBox="0 0 20 20" width="17" height="17" aria-hidden="true"><path :d="n.icon" /></svg>
          <span class="lbl">{{ n.label }}</span>
          <span v-if="'badge' in n && badge(n.badge)" class="nbadge" :class="n.badge" :title="n.badge === 'rogue' ? 'Rogue agents in the window' : 'Critical and high incidents in the window'">{{ badge(n.badge) }}</span>
        </RouterLink>
      </nav>
      <div class="spacer"></div>
      <button class="link" @click="logout">
        <svg viewBox="0 0 20 20" width="17" height="17" aria-hidden="true"><path d="M8 17H4V3h4M13 14l4-4-4-4M17 10H8" /></svg>
        Sign out
      </button>
    </aside>
    <main>
      <header class="row topbar">
        <button class="live" :class="{ stale: stale || hubUnreachable, broken: ingestBroken }" title="Refreshes every 30 seconds. Click to refresh now." @click="refreshTick++">
          <span class="dot" aria-hidden="true"></span>{{ stale ? 'Paused' : 'Live' }} <span class="muted">· {{ updated }}</span>
        </button>
        <div class="spacer"></div>
        <div class="seg" role="group" aria-label="Time window">
          <button v-for="w in [{ h: 1, l: '1h' }, { h: 24, l: '24h' }, { h: 168, l: '7d' }, { h: 720, l: '30d' }]" :key="w.h"
            :class="{ on: windowHours === w.h }" :aria-pressed="windowHours === w.h" @click="windowHours = w.h">{{ w.l }}</button>
        </div>
      </header>
      <div v-if="hubUnreachable" class="hub-alert" role="status">
        <strong>Can't reach the hub from this browser</strong> since {{ unreachableSince ? fmtTime(new Date(unreachableSince).toISOString()) : '—' }}
        — the SSH tunnel may have dropped, or the hub is restarting. Figures below are from the last successful refresh.
      </div>
      <div v-if="ingestBroken" class="ingest-alert" role="alert">
        <strong>Ingestion problem — the numbers below are incomplete</strong>
        <ul><li v-for="p in ingestProblems" :key="p">{{ p }}</li></ul>
      </div>
      <RouterView />
    </main>
  </div>
</template>

<style scoped>
.center { min-height: 100vh; display: grid; place-items: center; padding: 16px; }
.login-bg { background: radial-gradient(1200px 600px at 50% -10%, color-mix(in srgb, var(--c-rogue) 10%, transparent), transparent 70%), var(--bg); }
.login { width: 100%; max-width: 400px; display: grid; gap: 14px; padding: 32px 28px; text-align: center; }
.login h1 { margin: 0; font-size: 24px; }
.login p { margin: 0; }
.login input { text-align: center; padding: 10px; }
.login button { padding: 10px; font-weight: 600; }

/* The mark: a target with a filled core, the "trap". */
.mark { width: 30px; height: 30px; border-radius: 50%; border: 2px solid var(--c-rogue); display: grid; place-items: center; flex: none;
  background: color-mix(in srgb, var(--c-rogue) 8%, transparent); }
.mark span { width: 10px; height: 10px; border-radius: 50%; background: var(--c-rogue); }
.mark.big { width: 52px; height: 52px; margin: 0 auto 4px; border-width: 3px; }
.mark.big span { width: 18px; height: 18px; }

.shell { display: grid; grid-template-columns: 232px minmax(0, 1fr); min-height: 100vh; }
aside { background: var(--surface-1); border-right: 1px solid var(--border); padding: 20px 12px; display: flex; flex-direction: column; gap: 6px; position: sticky; top: 0; height: 100vh; }
.brand { display: flex; align-items: center; gap: 10px; padding: 0 8px 18px; }
.name { font-weight: 700; font-size: 16px; letter-spacing: -0.2px; }
.persona { font-size: 12px; color: var(--text-muted); }
nav { display: flex; flex-direction: column; gap: 2px; }
nav a { display: flex; align-items: center; gap: 10px; color: var(--text-secondary); padding: 8px 10px; border-radius: 8px; font-weight: 500; }
nav a svg, button.link svg { fill: none; stroke: currentColor; stroke-width: 1.6; stroke-linecap: round; stroke-linejoin: round; opacity: 0.8; flex: none; }
nav a:hover { background: var(--surface-2); text-decoration: none; color: var(--text-primary); }
nav a.active { background: var(--surface-2); color: var(--text-primary); font-weight: 600; }
nav a.active svg { opacity: 1; color: var(--accent); }
.lbl { flex: 1; }
.nbadge { min-width: 20px; padding: 0 6px; border-radius: 999px; font-size: 11.5px; font-weight: 700; line-height: 19px; text-align: center; font-variant-numeric: tabular-nums; }
.nbadge.rogue { background: var(--c-rogue); color: #fff; }
.nbadge.urgent { background: color-mix(in srgb, var(--serious) 22%, transparent); color: var(--text-primary); }
button.link { display: flex; align-items: center; gap: 10px; background: none; border: 0; color: var(--text-muted); text-align: left; padding: 8px 10px; }
button.link:hover { color: var(--text-primary); }
main { padding: 18px 28px 48px; min-width: 0; max-width: 1480px; }
.topbar { margin-bottom: 20px; }
.live { display: inline-flex; align-items: center; gap: 8px; background: transparent; border-color: transparent; padding: 5px 8px; font-size: 13px; color: var(--text-secondary); }
.live:hover { background: var(--surface-2); }
.dot { width: 8px; height: 8px; border-radius: 50%; background: var(--good); box-shadow: 0 0 0 0 color-mix(in srgb, var(--good) 60%, transparent); animation: pulse 2.4s ease-out infinite; }
.live.stale .dot { background: var(--text-muted); animation: none; }
.live.broken .dot { background: var(--c-rogue); }
.ingest-alert { margin: -6px 0 18px; padding: 12px 16px; border: 1px solid var(--c-rogue); border-radius: 10px;
  background: color-mix(in srgb, var(--c-rogue) 9%, var(--surface-1)); color: var(--text-primary); font-size: 13.5px; }
.ingest-alert strong { color: var(--c-rogue); }
.hub-alert { margin: -6px 0 18px; padding: 10px 16px; border: 1px solid var(--border); border-radius: 10px;
  background: var(--surface-2); color: var(--text-secondary); font-size: 13.5px; }
.hub-alert strong { color: var(--text-primary); }
.ingest-alert ul { margin: 6px 0 0; padding-left: 18px; color: var(--text-secondary); overflow-wrap: anywhere; }
@keyframes pulse { 0% { box-shadow: 0 0 0 0 color-mix(in srgb, var(--good) 55%, transparent); } 70%, 100% { box-shadow: 0 0 0 7px transparent; } }
.seg { display: inline-flex; background: var(--surface-2); border: 1px solid var(--border); border-radius: 8px; padding: 2px; }
.seg button { border: 0; background: transparent; padding: 4px 12px; border-radius: 6px; font-size: 13px; color: var(--text-secondary); }
.seg button.on { background: var(--surface-1); color: var(--text-primary); font-weight: 600; box-shadow: var(--shadow-hover); }
@media (max-width: 760px) {
  .shell { grid-template-columns: 1fr; }
  aside { position: static; height: auto; flex-direction: row; flex-wrap: wrap; align-items: center; padding: 12px; }
  .brand { padding: 0 8px 0 4px; }
  nav { flex-direction: row; flex-wrap: wrap; }
  nav a .lbl { position: absolute; width: 1px; height: 1px; overflow: hidden; clip-path: inset(50%); }
  .persona, button.link { display: none; }
  main { padding: 16px; }
}
</style>
