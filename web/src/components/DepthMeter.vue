<script setup lang="ts">
// The 0-7 depth ladder: how far into the synthetic estate an actor reached,
// drawn as seven segments. The number and tier name always accompany it.
const props = withDefaults(defineProps<{ depth: number; tier?: string | undefined; color?: string | undefined; size?: 'sm' | 'md' | 'lg'; showLabel?: boolean }>(), {
  tier: '', color: 'var(--c-agent)', size: 'md', showLabel: true,
})
const TIERS = ['reconnaissance', 'engaged the agent surface', 'used a sample credential', 'discovered real secrets',
  'used real credentials', 'lateral movement', 'privilege escalation', 'exfiltration']
</script>

<template>
  <span class="meter" :class="size" :title="`Depth ${props.depth} of 7: ${props.tier || TIERS[props.depth] || ''}`">
    <span class="segs" role="img" :aria-label="`Depth ${props.depth} of 7`">
      <span v-for="i in 7" :key="i" class="seg" :style="i <= props.depth ? { background: props.color } : undefined" />
    </span>
    <span v-if="showLabel" class="lbl"><b>{{ props.depth }}/7</b><template v-if="size === 'lg'"> · {{ props.tier || TIERS[props.depth] }}</template></span>
  </span>
</template>

<style scoped>
.meter { display: inline-flex; align-items: center; gap: 8px; white-space: nowrap; }
.segs { display: inline-flex; gap: 2px; }
.seg { width: 7px; height: 7px; border-radius: 2px; background: var(--track); }
.md .seg { width: 10px; }
.lg { flex-wrap: wrap; row-gap: 6px; white-space: normal; }
.lg .seg { width: 22px; height: 9px; border-radius: 3px; }
.lg .segs { gap: 3px; }
.lbl { font-size: 12px; color: var(--text-muted); font-variant-numeric: tabular-nums; }
.lbl b { color: var(--text-primary); font-weight: 600; }
.lg .lbl { font-size: 13.5px; color: var(--text-secondary); }
</style>
