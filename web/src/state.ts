import { ref } from 'vue'

// Shared UI state: the selected time window and a refresh tick that views watch.
export const windowHours = ref(24)
export const refreshTick = ref(0)
export const authed = ref(false)

// Pulse is what the navigation shows at a glance: rogue agents and urgent
// incidents in the window. Views that already load the data publish it here,
// so the badges never cost an extra request.
export const pulse = ref<{ rogue: number | null; urgent: number | null }>({ rogue: null, urgent: null })
// When data was last loaded, for the "updated" indicator.
export const lastLoaded = ref<number | null>(null)
