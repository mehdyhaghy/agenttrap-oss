<script setup lang="ts">
import { nextTick, onBeforeUnmount, ref, watch } from 'vue'
import rrwebPlayer from 'rrweb-player'
import 'rrweb-player/dist/style.css'
import { api } from '../api'

const props = defineProps<{ view: string }>()
const el = ref<HTMLDivElement | null>(null)
const error = ref('')
const count = ref(0)
let player: rrwebPlayer | null = null

async function load(): Promise<void> {
  try {
    const evs = await api.replay(props.view)
    count.value = evs.length
    error.value = ''
    await nextTick()
    if (!el.value) return
    el.value.innerHTML = ''
    player = new rrwebPlayer({
      target: el.value,
      props: { events: evs as never, width: 1024, height: 576, autoPlay: false, showController: true },
    })
  } catch (e) {
    error.value = (e as Error).message
  }
}
watch(() => props.view, load, { immediate: true })
onBeforeUnmount(() => {
  player?.getReplayer().pause()
  player = null
  if (el.value) el.value.innerHTML = ''
})
</script>

<template>
  <h1>Session recording <span class="mono">{{ view }}</span></h1>
  <p class="muted">{{ count }} recorded events. Typed input is masked at capture; only pointer, scroll, click and page changes are shown.</p>
  <p v-if="error" class="error">{{ error }}</p>
  <div class="card"><div ref="el" class="player"></div></div>
</template>

<style scoped>
.player { overflow: auto; }
h1 .mono { font-size: 16px; }
</style>
