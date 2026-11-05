<script setup lang="ts">
import { use } from 'echarts/core'
import { LineChart } from 'echarts/charts'
import { AriaComponent, GridComponent, LegendComponent, TooltipComponent } from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'
import VChart from 'vue-echarts'
import { useDark } from '@vueuse/core'
import { Maximize2, Minimize2 } from '@lucide/vue'
import type { Line } from '~/types/models'

use([LineChart, GridComponent, TooltipComponent, LegendComponent, AriaComponent, CanvasRenderer])

type Unit = 'pct' | 'bytes' | 'bps' | 'num'

const props = defineProps<{ title: string; lines: Line[]; unit: Unit; loading?: boolean; wide?: boolean; expandable?: boolean }>()
const emit = defineEmits<{ 'update:wide': [boolean] }>()
// a stable name lets the page animate this card between half and full width (View Transitions API)
const vtName = computed(() => `chart-${slug(props.title) || 'x'}`)
const dark = useDark()

// categorical palette in fixed order (validated light/dark steps); color follows series position in its chart
const PAL = {
  light: ['#2a78d6', '#eb6834', '#1baf7a', '#eda100', '#e87ba4', '#008300', '#6250d6', '#e34948'],
  dark: ['#3987e5', '#d95926', '#199e70', '#c98500', '#d55181', '#008300', '#9085e9', '#e66767'],
}

function fmt(v: number) {
  if (props.unit === 'pct') return `${Number.isInteger(v) ? v : v.toFixed(v < 10 ? 1 : 0)}%`
  if (props.unit === 'bytes') return bytes(v)
  if (props.unit === 'bps') return bytes(v, '/s')
  return num(v, v < 10 ? 2 : 0)
}

const option = computed(() => {
  const ink = dark.value ? '#9db4ba' : '#4a6572'
  const grid = dark.value ? '#12394a' : '#e3e8e9'
  // shortcut: more than 8 series (many mounts/ifaces) keep the first 8, upgrade to "Other" folding if fleets need it
  const lines = props.lines.slice(0, 8)
  return {
    aria: { enabled: true, label: { description: `${props.title} over time` } },
    color: dark.value ? PAL.dark : PAL.light,
    animation: false,
    // canvas text does not inherit CSS fonts
    textStyle: { fontFamily: '"IBM Plex Sans Variable", ui-sans-serif, system-ui, sans-serif' },
    grid: { left: 8, right: 12, top: lines.length > 1 ? 32 : 12, bottom: 8, containLabel: true },
    legend:
      lines.length > 1
        ? {
            type: 'scroll',
            top: 0,
            left: 0,
            textStyle: { color: ink },
            pageTextStyle: { color: ink },
            icon: 'roundRect',
            itemWidth: 12,
            itemHeight: 4,
          }
        : undefined,
    tooltip: {
      trigger: 'axis',
      axisPointer: { type: 'line' },
      valueFormatter: (v: number) => fmt(v),
      backgroundColor: dark.value ? '#0e3142' : '#fff',
      borderColor: grid,
      textStyle: { color: dark.value ? '#f3f4f4' : '#061e29' },
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
      // byte counts below 1/s would label the axis 0 B, 1 B, 1 B, 1 B
      minInterval: props.unit === 'bytes' || props.unit === 'bps' ? 1 : undefined,
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
  <Card class="gap-2 py-4" :style="{ viewTransitionName: vtName }">
    <CardHeader class="flex flex-row items-center justify-between gap-2 px-4">
      <CardTitle class="text-sm">{{ title }}</CardTitle>
      <Button
        v-if="expandable"
        variant="ghost"
        size="icon"
        class="-my-2 hidden size-7 text-muted-foreground lg:inline-flex"
        :aria-pressed="wide"
        :aria-label="wide ? `Show ${title} at half width` : `Show ${title} at full width`"
        :title="wide ? 'Show half width' : 'Show full width'"
        @click="emit('update:wide', !wide)"
      >
        <Minimize2 v-if="wide" class="size-4" />
        <Maximize2 v-else class="size-4" />
      </Button>
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
