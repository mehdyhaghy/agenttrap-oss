<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{ severity: string }>()
// Status colors never carry meaning alone: every badge has an icon and a label.
const meta = computed(() => {
  switch (props.severity) {
    case 'critical': return { icon: '●', label: 'Critical', color: 'var(--critical)' }
    case 'high': return { icon: '▲', label: 'High', color: 'var(--serious)' }
    case 'medium': return { icon: '◆', label: 'Medium', color: 'var(--warning)' }
    default: return { icon: '○', label: 'Exposure', color: 'var(--text-muted)' }
  }
})
</script>

<template>
  <span class="badge"><span class="icon" :style="{ color: meta.color }" aria-hidden="true">{{ meta.icon }}</span>{{ meta.label }}</span>
</template>

<style scoped>
.badge { display: inline-flex; align-items: center; gap: 6px; white-space: nowrap; font-weight: 500; }
.icon { font-size: 11px; }
</style>
