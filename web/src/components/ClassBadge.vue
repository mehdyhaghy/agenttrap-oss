<script setup lang="ts">
import { computed } from 'vue'
import { classMeta } from '../classes'

const props = defineProps<{ cls: string; confidence?: string }>()
const meta = computed(() => classMeta(props.cls))
</script>

<template>
  <span class="badge" :class="{ rogue: cls === 'rogue_agent' }">
    <span class="icon" :style="{ color: meta.color }" aria-hidden="true">{{ meta.icon }}</span>{{ meta.label }}
    <span v-if="confidence" class="conf muted">· {{ confidence }}</span>
  </span>
</template>

<style scoped>
.badge { display: inline-flex; align-items: center; gap: 6px; white-space: nowrap; }
.rogue { font-weight: 600; }
.icon { font-size: 12px; }
.conf { font-size: 12px; }
</style>
