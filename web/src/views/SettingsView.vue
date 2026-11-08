<script setup lang="ts">
import { ref, watch } from 'vue'
import { api, type OperatorRange } from '../api'
import { refreshTick } from '../state'
import { fmtTime } from '../format'

const ops = ref<OperatorRange[]>([])
const cidr = ref('')
const note = ref('')
const error = ref('')
const notice = ref('')

async function load(): Promise<void> {
  try {
    ops.value = (await api.operators()) ?? []
    error.value = ''
  } catch (e) {
    error.value = (e as Error).message
  }
}
watch(refreshTick, load, { immediate: true })

async function add(): Promise<void> {
  try {
    const res = await api.addOperator(cidr.value.trim(), note.value.trim())
    notice.value = `Added ${res.cidr}; ${res.incidents_removed} incident(s) removed.`
    cidr.value = ''
    note.value = ''
    await load()
  } catch (e) {
    error.value = (e as Error).message
  }
}

async function remove(c: string): Promise<void> {
  if (!window.confirm(`Stop treating ${c} as operator traffic?`)) return
  try {
    await api.removeOperator(c)
    await load()
  } catch (e) {
    error.value = (e as Error).message
  }
}
</script>

<template>
  <h1>Settings</h1>
  <div class="card">
    <h2>Operator addresses</h2>
    <p class="muted">Traffic from these addresses is yours (testing, monitoring). It never opens incidents, is classified as Operator, and is left out of the overview. Events are still stored.</p>
    <form class="row add" @submit.prevent="add">
      <input v-model="cidr" placeholder="IP or CIDR, e.g. 203.0.113.7 or 203.0.113.0/24" aria-label="IP or CIDR" required />
      <input v-model="note" placeholder="Note (optional)" aria-label="Note" />
      <button class="primary" type="submit" :disabled="!cidr">Add</button>
    </form>
    <p v-if="notice" class="muted">{{ notice }}</p>
    <p v-if="error" class="error">{{ error }}</p>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Range</th><th>Note</th><th>Added</th><th></th></tr></thead>
        <tbody>
          <tr v-for="o in ops" :key="o.cidr">
            <td class="mono">{{ o.cidr }}</td>
            <td class="muted">{{ o.note }}</td>
            <td class="muted">{{ fmtTime(o.created_at) }}</td>
            <td class="num"><button @click="remove(o.cidr)">Remove</button></td>
          </tr>
        </tbody>
      </table>
      <p v-if="!ops.length" class="empty">No operator addresses.</p>
    </div>
  </div>
</template>

<style scoped>
.add { margin: 12px 0; }
.add input:first-child { min-width: 320px; }
</style>
