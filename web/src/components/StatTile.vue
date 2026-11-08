<script setup lang="ts">
defineProps<{ label: string; value: string; hint?: string }>()
</script>

<template>
  <div class="card tile">
    <div class="label">{{ label }}</div>
    <div class="value">{{ value }}</div>
    <div v-if="hint" class="hint muted">{{ hint }}</div>
  </div>
</template>

<style scoped>
.tile { display: grid; gap: 2px; }
.label { color: var(--text-secondary); font-size: 12.5px; }
.value { font-size: 26px; font-weight: 600; font-variant-numeric: tabular-nums; }
.hint { font-size: 12px; }
</style>
