<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref, watch } from 'vue'
import * as echarts from 'echarts/core'
import { BarChart, LineChart } from 'echarts/charts'
import { GridComponent, TooltipComponent, BrushComponent, ToolboxComponent } from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'
import type { EChartsCoreOption } from 'echarts/core'

echarts.use([BarChart, LineChart, GridComponent, TooltipComponent, BrushComponent, ToolboxComponent, CanvasRenderer])

// brushable turns the chart into a Splunk-style time selector: drag across the
// x-axis to select a range, which is emitted (as [fromMs, toMs]) so the parent
// can drill into that window.
const props = defineProps<{ option: EChartsCoreOption; height?: number; label: string; brushable?: boolean }>()
const el = ref<HTMLDivElement | null>(null)
let chart: echarts.ECharts | undefined
let observer: ResizeObserver | undefined
const media = window.matchMedia('(prefers-color-scheme: dark)')
const emit = defineEmits<{ themechange: []; brush: [from: number, to: number] }>()
const onTheme = (): void => emit('themechange')

function armBrush(): void {
  if (!props.brushable || !chart) return
  // The parent's option is applied notMerge, so re-add the brush config and the
  // brush cursor after every setOption.
  chart.setOption({ toolbox: { show: false }, brush: { xAxisIndex: 0, brushType: 'lineX', brushMode: 'single', throttleType: 'debounce', throttleDelay: 200, removeOnClick: true } }, false)
  chart.dispatchAction({ type: 'takeGlobalCursor', key: 'brush', brushOption: { brushType: 'lineX', brushMode: 'single' } })
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function onBrushEnd(p: any): void {
  const range = p?.areas?.[0]?.coordRange as [number, number] | undefined
  if (range && range[0] !== range[1]) emit('brush', range[0], range[1])
  chart?.dispatchAction({ type: 'brush', areas: [] }) // clear the selection overlay
  armBrush() // re-arm the cursor for the next drag
}

onMounted(() => {
  if (!el.value) return
  chart = echarts.init(el.value, undefined, { renderer: 'canvas' })
  chart.setOption(props.option)
  armBrush()
  if (props.brushable) chart.on('brushEnd', onBrushEnd)
  observer = new ResizeObserver(() => chart?.resize())
  observer.observe(el.value)
  media.addEventListener('change', onTheme)
})
watch(() => props.option, (o) => { chart?.setOption(o, { notMerge: true }); armBrush() }, { deep: true })
onBeforeUnmount(() => {
  observer?.disconnect()
  media.removeEventListener('change', onTheme)
  chart?.dispose()
})
</script>

<template>
  <div ref="el" role="img" :aria-label="label" :style="{ height: `${height ?? 240}px`, width: '100%' }"></div>
</template>
