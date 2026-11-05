<script setup lang="ts">
import {
  ComboboxAnchor,
  ComboboxContent,
  ComboboxEmpty,
  ComboboxGroup,
  ComboboxInput,
  ComboboxItem,
  ComboboxLabel,
  ComboboxPortal,
  ComboboxRoot,
  ComboboxTrigger,
  ComboboxViewport,
} from 'reka-ui'
import { ChevronDown } from '@lucide/vue'
import type { MetricDef } from '~/types/models'

// searchable metric dropdown grouped by category; the search matches title, name, group and description
const props = defineProps<{ metrics: MetricDef[]; id?: string }>()
const model = defineModel<string>({ required: true })
const search = ref('')
const byName = computed(() => Object.fromEntries(props.metrics.map(m => [m.name, m])))

const groups = computed(() => {
  const q = search.value.trim().toLowerCase()
  const out: { name: string; items: MetricDef[] }[] = []
  for (const m of props.metrics) {
    if (q && ![m.title, m.name, m.group, m.description].some(s => s.toLowerCase().includes(q))) continue
    let g = out.find(x => x.name === m.group)
    if (!g) out.push((g = { name: m.group, items: [] }))
    g.items.push(m)
  }
  return out
})
const UNIT: Record<string, string> = {
  pct: '%',
  bytes: 'bytes',
  bytes_ps: 'bytes/s',
  count: 'count',
  per_s: 'per second',
  ms: 'ms',
  s: 'seconds',
  h: 'hours',
  days: 'days',
  ratio: '× usual',
  bool: 'up/down',
}
</script>

<template>
  <ComboboxRoot
    v-model="model"
    ignore-filter
    open-on-click
    reset-search-term-on-blur
    class="relative"
    @update:open="o => o && (search = '')"
  >
    <ComboboxAnchor
      class="flex h-9 w-full items-center rounded-md border border-input bg-transparent px-3 text-sm shadow-xs focus-within:border-ring focus-within:ring-3 focus-within:ring-ring/50 dark:bg-input/30"
    >
      <ComboboxInput
        :id="id"
        v-model="search"
        class="min-w-0 flex-1 bg-transparent outline-none placeholder:text-muted-foreground"
        :display-value="(v: string) => byName[v]?.title ?? v"
        placeholder="Search metrics (cpu, disk, redis…)"
        aria-label="Metric"
      />
      <ComboboxTrigger aria-label="Show metrics" class="text-muted-foreground"><ChevronDown class="size-4" /></ComboboxTrigger>
    </ComboboxAnchor>
    <ComboboxPortal>
      <ComboboxContent
        position="popper"
        :side-offset="4"
        class="z-50 max-h-80 w-(--reka-combobox-trigger-width) min-w-72 overflow-hidden rounded-md border bg-popover text-popover-foreground shadow-md"
      >
        <ComboboxViewport class="max-h-80 overflow-y-auto p-1">
          <ComboboxEmpty class="px-2 py-3 text-center text-sm text-muted-foreground">No metric matches.</ComboboxEmpty>
          <ComboboxGroup v-for="g in groups" :key="g.name">
            <ComboboxLabel class="px-2 pt-2 pb-1 text-xs font-medium text-muted-foreground">{{ g.name }}</ComboboxLabel>
            <ComboboxItem
              v-for="m in g.items"
              :key="m.name"
              :value="m.name"
              :text-value="m.title"
              class="flex cursor-default items-baseline justify-between gap-3 rounded-sm px-2 py-1.5 text-sm outline-none select-none data-highlighted:bg-accent data-[state=checked]:font-medium"
            >
              <span class="min-w-0">
                <span class="block truncate">{{ m.title }}</span>
                <span class="block truncate font-mono text-xs text-muted-foreground">{{ m.name }}</span>
              </span>
              <span class="shrink-0 text-xs text-muted-foreground">{{ UNIT[m.unit] }}</span>
            </ComboboxItem>
          </ComboboxGroup>
        </ComboboxViewport>
      </ComboboxContent>
    </ComboboxPortal>
  </ComboboxRoot>
</template>
