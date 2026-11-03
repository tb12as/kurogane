<script setup lang="ts">
const props = defineProps<{ diff?: string }>()
const lines = computed(() => (props.diff || '').split('\n'))
function cls(l: string) {
  if (l.startsWith('+') && !l.startsWith('+++')) return 'bg-ok/10 text-ok'
  if (l.startsWith('-') && !l.startsWith('---')) return 'bg-crit/10 text-crit'
  if (l.startsWith('@@')) return 'text-muted-foreground'
  return ''
}
</script>

<template>
  <pre
    v-if="diff"
    class="max-h-72 overflow-auto rounded-md border bg-muted/40 p-3 font-mono text-xs leading-5"
    tabindex="0"
    aria-label="Diff"
  ><div v-for="(l, i) in lines" :key="i" :class="cls(l)">{{ l || ' ' }}</div></pre>
  <p v-else class="text-sm text-muted-foreground">No file changes.</p>
</template>
