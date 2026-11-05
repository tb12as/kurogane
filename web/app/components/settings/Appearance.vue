<script setup lang="ts">
import { useColorMode } from '@vueuse/core'

// density and theme are remembered in this browser only
const density = useDensity()
// same storage key and class as useDark() in the layout, so both controls stay in sync
const mode = useColorMode({ emitAuto: true })
const themes = [
  { value: 'auto', label: 'System', hint: 'Follows the device setting' },
  { value: 'light', label: 'Light', hint: 'Always light' },
  { value: 'dark', label: 'Dark', hint: 'Always dark' },
] as const
// the preview scales like the real UI: its own --spacing and font size
const previewStyle: Record<Density, Record<string, string>> = {
  default: { fontSize: '16px', '--spacing': '0.25rem' },
  comfortable: { fontSize: '15px', '--spacing': '0.225rem' },
  compact: { fontSize: '14px', '--spacing': '0.2rem' },
}
</script>

<template>
  <Card>
    <CardHeader>
      <CardTitle>Layout density</CardTitle>
      <CardDescription>How much spacing and text size the interface uses. Saved in this browser.</CardDescription>
    </CardHeader>
    <CardContent>
      <fieldset class="grid gap-3 md:grid-cols-3">
        <legend class="sr-only">Layout density</legend>
        <label
          v-for="d in DENSITIES"
          :key="d.value"
          :class="[
            'cursor-pointer rounded-lg border p-3 transition-colors hover:bg-accent/50 has-[:focus-visible]:ring-2 has-[:focus-visible]:ring-ring',
            density === d.value ? 'border-primary ring-1 ring-primary' : '',
          ]"
        >
          <input v-model="density" type="radio" name="density" :value="d.value" class="sr-only" />
          <span class="flex items-baseline justify-between gap-2">
            <span class="font-medium">{{ d.label }}</span>
            <span class="text-xs text-muted-foreground">{{ d.hint }}</span>
          </span>
          <span class="mt-0.5 block text-xs text-muted-foreground">{{ d.description }}</span>
          <!-- preview: a stat tile and a table row at this density -->
          <span class="mt-3 block rounded-md border bg-card" :style="previewStyle[d.value]" aria-hidden="true">
            <span class="block border-b p-3">
              <span class="block" style="font-size: 0.75em; opacity: 0.7">CPU</span>
              <span class="block font-semibold" style="font-size: 1.4em">12.4%</span>
            </span>
            <span class="flex justify-between px-3 py-2" style="font-size: 0.85em">
              <span>web-01</span><span style="opacity: 0.7">online</span>
            </span>
          </span>
        </label>
      </fieldset>
    </CardContent>
  </Card>

  <Card>
    <CardHeader>
      <CardTitle>Theme</CardTitle>
      <CardDescription>Light, dark, or the same as your device. Saved in this browser.</CardDescription>
    </CardHeader>
    <CardContent>
      <fieldset class="grid gap-3 sm:grid-cols-3">
        <legend class="sr-only">Theme</legend>
        <label
          v-for="t in themes"
          :key="t.value"
          :class="[
            'cursor-pointer rounded-lg border p-3 transition-colors hover:bg-accent/50 has-[:focus-visible]:ring-2 has-[:focus-visible]:ring-ring',
            mode === t.value ? 'border-primary ring-1 ring-primary' : '',
          ]"
        >
          <input v-model="mode" type="radio" name="theme" :value="t.value" class="sr-only" />
          <span class="block font-medium">{{ t.label }}</span>
          <span class="block text-xs text-muted-foreground">{{ t.hint }}</span>
        </label>
      </fieldset>
    </CardContent>
  </Card>
</template>
