<script setup lang="ts">
// A number with a thin magnitude bar, for ranked tables.
defineProps<{ value: number; max: number }>()
</script>

<template>
  <div class="bar-cell">
    <span class="n">{{ value.toLocaleString() }}</span>
    <span class="track"><span class="fill" :style="{ width: `${max > 0 ? Math.max(3, (value / max) * 100) : 0}%` }"></span></span>
  </div>
</template>

<style scoped>
.bar-cell { display: grid; grid-template-columns: 52px 1fr; gap: 8px; align-items: center; min-width: 120px; }
.n { text-align: right; font-variant-numeric: tabular-nums; }
.track { height: 6px; background: var(--surface-2); border-radius: 4px; overflow: hidden; }
.fill { display: block; height: 100%; background: var(--series-1); border-radius: 4px; }
</style>
