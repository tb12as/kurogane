<script setup lang="ts">
// single headline value; optional meter for 0-100 values
const props = defineProps<{
  label: string
  value: string
  sub?: string
  meter?: number
  warn?: number
  crit?: number
}>()
const tone = computed(() => {
  const m = props.meter ?? 0
  if (props.crit !== undefined && m >= props.crit) return 'bg-crit'
  if (props.warn !== undefined && m >= props.warn) return 'bg-warn'
  return 'bg-primary/70'
})
</script>

<template>
  <Card class="gap-1 py-4">
    <CardContent class="space-y-1 px-4">
      <p class="text-xs font-medium text-muted-foreground">{{ label }}</p>
      <p class="text-2xl font-semibold tabular-nums">{{ value }}</p>
      <div
        v-if="meter !== undefined"
        class="h-1.5 w-full overflow-hidden rounded-full bg-muted"
        role="meter"
        :aria-label="label"
        aria-valuemin="0"
        aria-valuemax="100"
        :aria-valuenow="Math.round(meter)"
      >
        <div class="h-full rounded-full" :class="tone" :style="{ width: Math.min(100, Math.max(0, meter)) + '%' }" />
      </div>
      <p v-if="sub" class="truncate text-xs text-muted-foreground">{{ sub }}</p>
    </CardContent>
  </Card>
</template>
