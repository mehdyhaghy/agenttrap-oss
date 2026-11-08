// Page telemetry: behavior signals that separate people from automation, and
// an rrweb recording of the session. Only timings, counts and geometry are
// collected; typed text and input values are never recorded.
import { record } from '@rrweb/record'

const script = document.currentScript as HTMLScriptElement | null
const viewID = script?.dataset['v'] ?? ''
const t0 = performance.now()

// ---- Behavior signals -----------------------------------------------------

let untrusted = 0 // events dispatched by script (isTrusted false)
let firstInput = -1 // ms from load to the first user input
let moves = 0
let pathLen = 0 // total pointer travel, px
let firstPt: [number, number] | null = null
let lastPt: [number, number] | null = null
let lastMoveT = 0
let jumps = 0 // pointer moves of > 300 px between consecutive samples (teleports)
let clicks = 0
let clickOffsetSum = 0 // distance from the clicked element's center, px
let clickNoHover = 0 // clicks with no pointer movement over the element first
let keys = 0
let pastes = 0
const keyGaps: number[] = []
let lastKeyT = 0
let scrolls = 0
let scrollJumps = 0 // scroll steps of > 1000 px (programmatic)
let lastScrollY = window.scrollY
let hovered: Element | null = null

function markInput(e: Event): void {
  if (!e.isTrusted) untrusted++
  if (firstInput < 0) firstInput = Math.round(performance.now() - t0)
}

addEventListener('mousemove', (e) => {
  markInput(e)
  moves++
  const p: [number, number] = [e.clientX, e.clientY]
  if (lastPt) {
    const d = Math.hypot(p[0] - lastPt[0], p[1] - lastPt[1])
    pathLen += d
    if (d > 300) jumps++
  } else {
    firstPt = p
  }
  lastPt = p
  lastMoveT = performance.now()
  hovered = e.target instanceof Element ? e.target : null
}, { passive: true, capture: true })

addEventListener('click', (e) => {
  markInput(e)
  clicks++
  const el = e.target instanceof Element ? e.target : null
  if (el) {
    const r = el.getBoundingClientRect()
    clickOffsetSum += Math.hypot(e.clientX - (r.left + r.width / 2), e.clientY - (r.top + r.height / 2))
    if (hovered !== el && !(hovered && el.contains(hovered)) && performance.now() - lastMoveT > 50) clickNoHover++
  }
}, { capture: true })

addEventListener('keydown', (e) => {
  markInput(e)
  keys++
  const now = performance.now()
  if (lastKeyT > 0 && now - lastKeyT < 2000) keyGaps.push(now - lastKeyT)
  lastKeyT = now
}, { capture: true })

addEventListener('paste', (e) => {
  markInput(e)
  pastes++
}, { capture: true })

addEventListener('scroll', () => {
  scrolls++
  if (Math.abs(window.scrollY - lastScrollY) > 1000) scrollJumps++
  lastScrollY = window.scrollY
}, { passive: true })

function stats(xs: number[]): [number, number] {
  if (xs.length === 0) return [0, 0]
  const mean = xs.reduce((a, b) => a + b, 0) / xs.length
  const sd = Math.sqrt(xs.reduce((a, b) => a + (b - mean) ** 2, 0) / xs.length)
  return [Math.round(mean), Math.round(sd)]
}

function beaconPayload(phase: string): string {
  const n = navigator
  let tz = ''
  try {
    tz = Intl.DateTimeFormat().resolvedOptions().timeZone
  } catch {
    /* ignore */
  }
  const [keyMean, keySD] = stats(keyGaps)
  const disp = firstPt && lastPt ? Math.hypot(lastPt[0] - firstPt[0], lastPt[1] - firstPt[1]) : 0
  return JSON.stringify({
    v: viewID, ph: phase, wd: !!n.webdriver, l: (n.languages ?? []).length, p: n.plugins?.length ?? 0,
    hc: n.hardwareConcurrency || 0, tz, sw: screen.width, sh: screen.height, tp: n.maxTouchPoints || 0,
    vs: document.visibilityState, dt: Math.round(performance.now() - t0),
    m: moves, k: keys, s: scrolls, c: clicks,
    ut: untrusted, fi: firstInput, pl: Math.round(pathLen), pd: Math.round(disp), pj: jumps,
    co: clicks ? Math.round(clickOffsetSum / clicks) : -1, cn: clickNoHover,
    kn: keyGaps.length, km: keyMean, ks: keySD, pa: pastes, sj: scrollJumps,
  })
}

function sendBeacon(phase: string): void {
  try {
    navigator.sendBeacon('/_rum', beaconPayload(phase))
  } catch {
    /* ignore */
  }
}

setTimeout(() => sendBeacon('load'), 1500)

// ---- Session recording (rrweb) ----------------------------------------------

type RREvent = { type: number; timestamp: number }
let buf: RREvent[] = []
let bufBytes = 0
let seq = 0
const maxChunk = 48_000 // stay under the 64 KB keepalive/sendBeacon limit
const maxSeq = 60 // stop after ~60 chunks per page view

function flush(final: boolean): void {
  if (buf.length === 0 || seq >= maxSeq) return
  const body = JSON.stringify({ v: viewID, s: seq++, e: buf })
  buf = []
  bufBytes = 0
  try {
    if (final) navigator.sendBeacon('/_rum/r', body)
    else void fetch('/_rum/r', { method: 'POST', body, keepalive: true, headers: { 'Content-Type': 'text/plain' } })
  } catch {
    /* ignore */
  }
}

try {
  record<RREvent>({
    emit(event) {
      buf.push(event)
      bufBytes += JSON.stringify(event).length
      if (bufBytes > maxChunk) flush(false)
    },
    maskAllInputs: true,
    maskTextSelector: 'input, textarea',
    sampling: { mousemove: 50, scroll: 150, input: 'last' },
    recordCanvas: false,
    collectFonts: false,
  })
} catch {
  /* recording unavailable; behavior signals still work */
}
setInterval(() => flush(false), 5000)

addEventListener('pagehide', () => {
  flush(true)
  sendBeacon('hide')
})
