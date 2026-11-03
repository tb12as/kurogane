<script setup lang="ts">
// state/severity badge: color plus the word itself, never color alone
const props = defineProps<{ value?: string | null }>()
const tone: Record<string, string> = {
  firing: 'crit',
  critical: 'crit',
  fail: 'crit',
  failed: 'crit',
  error: 'crit',
  rolled_back: 'crit',
  down: 'crit',
  offline: 'crit',
  high: 'crit',
  weak: 'crit',
  warning: 'warn',
  warn: 'warn',
  acknowledged: 'warn',
  pending: 'warn',
  medium: 'warn',
  stale: 'warn',
  expired: 'warn',
  pass: 'ok',
  ok: 'ok',
  resolved: 'ok',
  confirmed: 'ok',
  active: 'ok',
  online: 'ok',
  done: 'ok',
  applied: 'ok',
  success: 'ok',
  ready: 'ok',
  connected: 'ok',
  'not ready': 'warn',
  disconnected: 'warn',
}
const cls: Record<string, string> = {
  crit: 'border-crit/40 bg-crit/10 text-crit',
  warn: 'border-warn/40 bg-warn/10 text-warn',
  ok: 'border-ok/40 bg-ok/10 text-ok',
  none: 'text-muted-foreground',
}
const c = computed(() => cls[tone[(props.value || '').toLowerCase()] || 'none'])
</script>

<template>
  <Badge variant="outline" :class="c">{{ (value || '-').replace(/_/g, ' ') }}</Badge>
</template>
