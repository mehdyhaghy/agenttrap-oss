<script setup lang="ts">
import { flag } from '../format'

// A source address with its country flag, linked to the source page.
defineProps<{ ip: string; cc?: string | undefined; country?: string | undefined; link?: boolean }>()
</script>

<template>
  <span class="addr mono">
    <span v-if="cc" class="flag" :title="country || cc" :aria-label="country || cc">{{ flag(cc) }}</span>
    <RouterLink v-if="link !== false" :to="`/sources/${encodeURIComponent(ip)}`" @click.stop>{{ ip }}</RouterLink>
    <template v-else>{{ ip }}</template>
  </span>
</template>
