<script setup lang="ts">
// Playback controls for the attack-map replay: an activity histogram that
// doubles as the seek bar (click or drag), play/pause, step, speed, loop and
// trail mode. The parent owns the state; this only draws and emits.
import { computed, ref } from 'vue'
import { fmtMinute, fmtNum } from '../format'

const props = defineProps<{
  activity: number[]
  since: string
  stepSeconds: number
}>()
const frame = defineModel<number>('frame', { required: true })
const playing = defineModel<boolean>('playing', { required: true })
const speed = defineModel<number>('speed', { required: true })
const loop = defineModel<boolean>('loop', { required: true })
const mode = defineModel<'trail' | 'cumulative'>('mode', { required: true })

const n = computed(() => props.activity.length)
const peak = computed(() => Math.max(1, ...props.activity))
const t0 = computed(() => new Date(props.since).getTime())
const at = (f: number): Date => new Date(t0.value + f * props.stepSeconds * 1000)
// A square-root scale keeps quiet hours visible next to a burst.
const bar = (v: number): number => (v > 0 ? Math.max(1.5, 38 * Math.sqrt(v / peak.value)) : 0)
const ticks = computed(() => {
  const count = 5
  return Array.from({ length: count }, (_, i) => {
    const f = Math.round((i * (n.value - 1)) / (count - 1))
    return { f, pct: (100 * f) / Math.max(1, n.value), label: fmtMinute(at(f)) }
  })
})

const svg = ref<SVGSVGElement | null>(null)
let dragging = false
function seekTo(e: PointerEvent): void {
  const r = svg.value?.getBoundingClientRect()
  if (!r || n.value === 0) return
  frame.value = Math.min(n.value - 1, Math.max(0, Math.floor(((e.clientX - r.left) / r.width) * n.value)))
}
function down(e: PointerEvent): void {
  dragging = true
  playing.value = false
  seekTo(e)
  try {
    svg.value?.setPointerCapture(e.pointerId) // keep dragging when the pointer leaves the bar
  } catch {
    /* no active pointer with that id: seeking still works, dragging just stops at the edge */
  }
}
function move(e: PointerEvent): void {
  if (dragging) seekTo(e)
}
function up(e: PointerEvent): void {
  dragging = false
  if (svg.value?.hasPointerCapture(e.pointerId)) svg.value.releasePointerCapture(e.pointerId)
}
function step(d: number): void {
  playing.value = false
  frame.value = Math.min(n.value - 1, Math.max(0, frame.value + d))
}
function toggle(): void {
  if (!playing.value && frame.value >= n.value - 1) frame.value = 0 // replay from the start
  playing.value = !playing.value
}
const speeds = [1, 2, 4, 8]
</script>

<template>
  <div class="scrubber">
    <div class="bar-row">
      <button type="button" class="icon" :aria-label="playing ? 'Pause' : 'Play'" :title="playing ? 'Pause (Space)' : 'Play (Space)'" @click="toggle">
        <svg v-if="playing" viewBox="0 0 20 20" width="16" height="16" aria-hidden="true"><rect x="5" y="4" width="3.5" height="12" rx="1" /><rect x="11.5" y="4" width="3.5" height="12" rx="1" /></svg>
        <svg v-else viewBox="0 0 20 20" width="16" height="16" aria-hidden="true"><path d="M6 4l10 6-10 6z" /></svg>
      </button>
      <button type="button" class="icon" aria-label="Previous frame" title="Previous frame (←)" @click="step(-1)">
        <svg viewBox="0 0 20 20" width="15" height="15" aria-hidden="true"><path d="M5 4h2v12H5zM16 4v12L8 10z" /></svg>
      </button>
      <button type="button" class="icon" aria-label="Next frame" title="Next frame (→)" @click="step(1)">
        <svg viewBox="0 0 20 20" width="15" height="15" aria-hidden="true"><path d="M13 4h2v12h-2zM4 4v12l8-6z" /></svg>
      </button>
      <div class="seg" role="group" aria-label="Speed">
        <button v-for="s in speeds" :key="s" type="button" :class="{ active: speed === s }" :aria-pressed="speed === s" @click="speed = s">{{ s }}×</button>
      </div>
      <div class="seg" role="group" aria-label="What stays on the map">
        <button type="button" :class="{ active: mode === 'trail' }" :aria-pressed="mode === 'trail'"
          title="Recent activity fades out" @click="mode = 'trail'">Trail</button>
        <button type="button" :class="{ active: mode === 'cumulative' }" :aria-pressed="mode === 'cumulative'"
          title="Everything so far stays on the map" @click="mode = 'cumulative'">Cumulative</button>
      </div>
      <label class="loop"><input v-model="loop" type="checkbox" /> Loop</label>
      <span class="spacer"></span>
      <span class="pos muted">Frame {{ frame + 1 }} / {{ n }} · {{ fmtNum(activity[frame] ?? 0) }} events</span>
    </div>

    <div class="hist">
      <svg ref="svg" :viewBox="`0 0 ${n} 40`" preserveAspectRatio="none" role="slider" tabindex="-1"
        aria-label="Replay position" :aria-valuemin="1" :aria-valuemax="n" :aria-valuenow="frame + 1"
        :aria-valuetext="fmtMinute(at(frame))" @pointerdown="down" @pointermove="move" @pointerup="up" @pointercancel="up">
        <rect x="0" y="0" :width="n" height="40" class="bg" />
        <rect v-for="(v, i) in activity" :key="i" :x="i + 0.12" :y="40 - bar(v)" width="0.76" :height="bar(v)"
          :class="i <= frame ? 'past' : 'future'" />
        <rect :x="frame" y="0" width="1" height="40" class="head" />
      </svg>
      <div class="ticks" aria-hidden="true">
        <span v-for="t in ticks" :key="t.f" :style="{ left: `${t.pct}%` }">{{ t.label }}</span>
      </div>
    </div>
  </div>
</template>

<style scoped>
.scrubber { display: grid; gap: 8px; margin-top: 10px; }
.bar-row { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; }
.icon { display: inline-grid; place-items: center; width: 32px; height: 30px; padding: 0; }
.icon svg { fill: currentColor; }
.seg { display: inline-flex; border: 1px solid var(--border); border-radius: 6px; overflow: hidden; }
.seg button { border: 0; border-radius: 0; background: var(--surface-2); padding: 5px 10px; font-size: 12.5px; }
.seg button.active { background: var(--accent); color: #fff; }
.loop { display: inline-flex; align-items: center; gap: 5px; font-size: 12.5px; color: var(--text-secondary); }
.spacer { flex: 1; }
.pos { font-size: 12.5px; font-variant-numeric: tabular-nums; }
.hist { position: relative; padding-bottom: 18px; }
.hist svg { display: block; width: 100%; height: 56px; cursor: pointer; touch-action: none; }
.bg { fill: var(--surface-2); }
.past { fill: var(--accent); }
.future { fill: color-mix(in srgb, var(--text-muted) 45%, transparent); }
.head { fill: var(--c-rogue); }
.ticks { position: absolute; left: 0; right: 0; bottom: 0; height: 16px; font-size: 11px; color: var(--text-muted); }
.ticks span { position: absolute; transform: translateX(-50%); white-space: nowrap; }
.ticks span:first-child { transform: none; }
.ticks span:last-child { transform: translateX(-100%); }
</style>
