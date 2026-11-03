<script setup lang="ts">
import { use } from 'echarts/core'
import { LineChart } from 'echarts/charts'
import { AriaComponent, GridComponent, LegendComponent, TooltipComponent } from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'
import VChart from 'vue-echarts'
import { useDark } from '@vueuse/core'
import type { Line } from '~/types/models'

use([LineChart, GridComponent, TooltipComponent, LegendComponent, AriaComponent, CanvasRenderer])

type Unit = 'pct' | 'bytes' | 'bps' | 'num'

const props = defineProps<{ title: string; lines: Line[]; unit: Unit; loading?: boolean }>()
const dark = useDark()

// categorical palette in fixed order (validated light/dark steps); color follows series position in its chart
const PAL = {
  light: ['#2a78d6', '#eb6834', '#1baf7a', '#eda100', '#e87ba4', '#008300', '#6250d6', '#e34948'],
  dark: ['#3987e5', '#d95926', '#199e70', '#c98500', '#d55181', '#008300', '#9085e9', '#e66767'],
}

function fmt(v: number) {
  if (props.unit === 'pct') return `${v.toFixed(v < 10 ? 1 : 0)}%`
  if (props.unit === 'bytes') return bytes(v)
  if (props.unit === 'bps') return bytes(v, '/s')
  return num(v, v < 10 ? 2 : 0)
}

const option = computed(() => {
  const ink = dark.value ? '#c3c2b7' : '#52514e'
  const grid = dark.value ? '#2e2e2c' : '#ececea'
  // shortcut: more than 8 series (many mounts/ifaces) keep the first 8, upgrade to "Other" folding if fleets need it
  const lines = props.lines.slice(0, 8)
  return {
    aria: { enabled: true, label: { description: `${props.title} over time` } },
    color: dark.value ? PAL.dark : PAL.light,
    animation: false,
    grid: { left: 8, right: 12, top: lines.length > 1 ? 32 : 12, bottom: 8, containLabel: true },
    legend:
      lines.length > 1
        ? { top: 0, left: 0, textStyle: { color: ink }, icon: 'roundRect', itemWidth: 12, itemHeight: 4 }
        : undefined,
    tooltip: {
      trigger: 'axis',
      axisPointer: { type: 'line' },
      valueFormatter: (v: number) => fmt(v),
      backgroundColor: dark.value ? '#1a1a19' : '#fff',
      borderColor: grid,
      textStyle: { color: dark.value ? '#f0efec' : '#0b0b0b' },
    },
    xAxis: {
      type: 'time',
      axisLine: { lineStyle: { color: grid } },
      axisLabel: { color: ink, hideOverlap: true },
      splitLine: { show: false },
    },
    yAxis: {
      type: 'value',
      min: 0,
      max: props.unit === 'pct' ? 100 : undefined,
      axisLabel: { color: ink, formatter: (v: number) => fmt(v) },
      splitLine: { lineStyle: { color: grid } },
    },
    series: lines.map(l => ({
      name: l.name,
      type: 'line',
      data: l.data,
      showSymbol: false,
      lineStyle: { width: 2 },
      sampling: 'lttb',
    })),
  }
})
const empty = computed(() => !props.lines.some(l => l.data.length))
</script>

<template>
  <Card class="gap-2 py-4">
    <CardHeader class="px-4">
      <CardTitle class="text-sm">{{ title }}</CardTitle>
    </CardHeader>
    <CardContent class="px-2">
      <Skeleton v-if="loading && empty" class="h-56 w-full" />
      <p v-else-if="empty" class="flex h-56 items-center justify-center text-sm text-muted-foreground">
        No data for this range.
      </p>
      <ClientOnly v-else>
        <!-- vue-echarts sets an unlayered height:100% that beats tailwind utilities, so size the parent -->
        <div class="h-56 w-full"><VChart :option="option" autoresize /></div>
      </ClientOnly>
    </CardContent>
  </Card>
</template>
