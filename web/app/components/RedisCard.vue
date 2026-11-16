<script setup lang="ts">
import type { RedisInstance } from '~/types/models'

// one monitored Redis instance from the live snapshot
const props = defineProps<{ r: RedisInstance }>()

const state = computed(() => {
  switch (props.r.status) {
    case 'up':
      return 'online'
    case 'needs_credentials':
      return 'not ready'
    case 'auth_failed':
      return 'failed'
  }
  return 'down'
})
const memPct = computed(() => (props.r.maxmemory > 0 ? (100 * props.r.memory_used) / props.r.maxmemory : null))
const role = computed(() => {
  if (props.r.role === 'slave') return `replica · link ${props.r.master_link || '?'}`
  if (props.r.role === 'master') return props.r.replicas ? `primary · ${props.r.replicas} replica(s)` : 'primary'
  return props.r.role || ''
})
const persistence = computed(() => {
  const r = props.r
  const parts = [r.last_save && when(r.last_save) ? `saved ${ago(r.last_save)}` : 'never saved']
  if (r.changes_since_save) parts.push(`${num(r.changes_since_save)} unsaved changes`)
  if (r.aof_enabled) parts.push(`AOF ${r.aof_status === 'ok' ? 'ok' : 'FAILING'}`)
  return parts.join(' · ')
})
const saveFailed = computed(() => (props.r.rdb_status && props.r.rdb_status !== 'ok') || (props.r.aof_enabled && props.r.aof_status !== 'ok'))
const totals = computed(() => {
  const r = props.r
  return [
    { label: 'Commands', value: num(r.total_commands) },
    { label: 'Connections', value: num(r.total_connections) },
    { label: 'Rejected connections', value: num(r.rejected_connections) },
    { label: 'Network in', value: bytes(r.net_input_bytes) },
    { label: 'Network out', value: bytes(r.net_output_bytes) },
    { label: 'Key hits / misses', value: `${num(r.keyspace_hits)} / ${num(r.keyspace_misses)}` },
    { label: 'Expired keys', value: num(r.expired_keys) },
    { label: 'Evicted keys', value: num(r.evicted_keys) },
  ]
})
function ms(ns: number) {
  if (ns < 1e6) return `${Math.round(ns / 1e3)} µs`
  return `${(ns / 1e6).toFixed(ns < 1e7 ? 1 : 0)} ms`
}
</script>

<template>
  <Card>
    <CardHeader class="flex flex-row flex-wrap items-start justify-between gap-2">
      <div class="min-w-0">
        <CardTitle class="truncate">Redis · {{ r.name }}</CardTitle>
        <p class="truncate text-xs text-muted-foreground">
          {{ r.addr }}<template v-if="r.version"> · {{ r.version }}</template><template v-if="role"> · {{ role }}</template>
          <template v-if="r.uptime_s"> · up {{ uptime(r.uptime_s) }}</template>
          <template v-if="when(r.started_at)"> (since {{ fmtDate(r.started_at) }})</template>
        </p>
      </div>
      <StateBadge :value="state" />
    </CardHeader>
    <CardContent class="space-y-4 text-sm">
      <Alert v-if="r.status !== 'up'" :variant="r.status === 'needs_credentials' ? 'default' : 'destructive'">
        <AlertTitle>
          {{
            r.status === 'needs_credentials'
              ? 'Needs credentials: not monitored yet'
              : r.status === 'auth_failed'
                ? 'Credentials rejected'
                : 'Not answering'
          }}
        </AlertTitle>
        <AlertDescription>
          <span v-if="r.error">{{ r.error }}. </span>
          <span v-if="r.hint" class="break-words">{{ r.hint }}</span>
        </AlertDescription>
      </Alert>

      <template v-else>
        <div>
          <div class="mb-1 flex justify-between text-xs">
            <span>Memory {{ bytes(r.memory_used) }}<template v-if="r.maxmemory"> of {{ bytes(r.maxmemory) }}</template></span>
            <span class="text-muted-foreground">{{ r.maxmemory ? r.maxmemory_policy : 'no maxmemory limit' }}</span>
          </div>
          <div
            v-if="memPct !== null"
            class="h-2 overflow-hidden rounded-full bg-muted"
            role="meter"
            :aria-valuenow="Math.round(memPct)"
            aria-valuemin="0"
            aria-valuemax="100"
            :aria-label="`Redis ${r.name} memory used`"
          >
            <div
              :class="['h-full', memPct > 90 ? 'bg-crit' : memPct > 75 ? 'bg-warn' : 'bg-muted-foreground']"
              :style="{ width: `${Math.min(memPct, 100)}%` }"
            />
          </div>
        </div>

        <dl class="grid grid-cols-2 gap-x-4 gap-y-2 sm:grid-cols-4">
          <div>
            <dt class="text-xs text-muted-foreground">Ops/s</dt>
            <dd class="tabular-nums">{{ num(r.ops_ps, 1) }}</dd>
          </div>
          <div>
            <dt class="text-xs text-muted-foreground">Hit ratio</dt>
            <dd class="tabular-nums">{{ r.hit_ratio === undefined || r.hit_ratio === null ? '-' : pct(r.hit_ratio) }}</dd>
          </div>
          <div>
            <dt class="text-xs text-muted-foreground">Clients</dt>
            <dd class="tabular-nums">{{ num(r.clients) }} / {{ num(r.maxclients) }}</dd>
          </div>
          <div>
            <dt class="text-xs text-muted-foreground">PING</dt>
            <dd class="tabular-nums">{{ num(r.ping_ms, 2) }} ms</dd>
          </div>
        </dl>

        <div>
          <p class="mb-1 text-xs text-muted-foreground">Totals since start</p>
          <dl class="grid grid-cols-2 gap-x-4 gap-y-2 sm:grid-cols-4">
            <div v-for="t in totals" :key="t.label">
              <dt class="text-xs text-muted-foreground">{{ t.label }}</dt>
              <dd class="tabular-nums">{{ t.value }}</dd>
            </div>
          </dl>
        </div>

        <p :class="['text-xs', saveFailed ? 'text-crit' : 'text-muted-foreground']">
          <template v-if="saveFailed">Saving to disk is failing: </template>{{ persistence }}
        </p>

        <div v-if="r.keyspace.length" class="flex flex-wrap gap-1">
          <Badge v-for="d in r.keyspace" :key="d.name" variant="secondary" class="tabular-nums">
            {{ d.name }}: {{ num(d.keys) }} keys
          </Badge>
        </div>

        <details v-if="r.slowlog.length">
          <summary class="cursor-pointer text-xs text-muted-foreground">Slow log ({{ r.slowlog.length }})</summary>
          <Table class="mt-2">
            <TableHeader>
              <TableRow>
                <TableHead>When</TableHead>
                <TableHead>Command</TableHead>
                <TableHead class="text-right">Took</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              <TableRow v-for="e in r.slowlog" :key="e.id">
                <TableCell class="whitespace-nowrap">{{ ago(e.at) }}</TableCell>
                <TableCell class="font-mono">{{ e.command }}</TableCell>
                <TableCell class="text-right tabular-nums">{{ ms(e.duration_ns) }}</TableCell>
              </TableRow>
            </TableBody>
          </Table>
          <p class="mt-1 text-xs text-muted-foreground">Command names only: arguments are never collected.</p>
        </details>
      </template>
    </CardContent>
  </Card>
</template>
