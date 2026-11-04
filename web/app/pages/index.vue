<script setup lang="ts">
import type { AlertEvent, Server, Snapshot } from '~/types/models'

useHead({ title: 'Overview · Kurogane' })
const fleet = useFleet()
const live = useLive()

const { data: status, error: stErr, refresh: refreshStatus } = useAsyncData('status', () => api.get('/status'))
const {
  data: servers,
  pending: srvPending,
  error: srvErr,
} = useAsyncData('fleet.overview', async () =>
  fleet.value ? list<Server>(await api.get('/fleet/overview'), 'servers') : [],
)

// seed the cards before the first SSE frame
onMounted(async () => {
  if (fleet.value || live.snap.value) return
  try {
    live.snap.value = (await api.get('/metrics/current')) as Snapshot
  } catch {
    /* cards show a placeholder until the stream delivers */
  }
})

// onboarding telemetry: time from init to first dashboard (backend records only the first call)
onMounted(() => {
  try {
    if (localStorage.getItem('krgn.first-dashboard')) return
    localStorage.setItem('krgn.first-dashboard', '1')
  } catch {
    /* storage blocked */
  }
  api.post('/telemetry/first-dashboard').catch(() => {})
})

watch(
  () => live.tick.value.alert + live.tick.value.harden,
  () => refreshStatus(),
)

const s = computed(() => live.snap.value)
const m = (k: string, l?: Record<string, string>) => metric(s.value, k, l)
const rootMount = computed(() => {
  const ms = s.value?.mounts || []
  return ms.find(x => x.path === '/') || ms.slice().sort((a, b) => b.used_pct - a.used_pct)[0]
})
const fullest = computed(() => (s.value?.mounts || []).slice().sort((a, b) => b.used_pct - a.used_pct)[0])
const alerts = computed(() => list<AlertEvent>(status.value?.active_alerts))
const hard = computed(() => status.value?.hardening)
</script>

<template>
  <div class="flex flex-wrap items-end justify-between gap-2">
    <div>
      <h1 class="text-2xl font-semibold">
        {{ fleet ? 'Fleet overview' : status?.server_name || s?.system?.hostname || 'Overview' }}
      </h1>
      <p v-if="!fleet && s?.system" class="text-sm text-muted-foreground">
        {{ s.system.os }} · kernel {{ s.system.kernel }} · up {{ uptime(s.system.uptime_s) }}
        <span v-if="s.system.reboot_required" class="text-warn">· reboot required</span>
        <span v-if="s.system.security_updates" class="text-warn">
          · {{ s.system.security_updates }} security updates
        </span>
      </p>
    </div>
    <Button v-if="!fleet" as-child variant="outline" size="sm">
      <NuxtLink to="/servers/local">Charts and processes</NuxtLink>
    </Button>
  </div>

  <Alert v-if="stErr" variant="destructive">
    <AlertDescription>{{ errMsg(stErr) }}</AlertDescription>
  </Alert>

  <div class="grid gap-4 lg:grid-cols-3">
    <Card :class="fleet ? 'lg:col-span-3' : 'lg:col-span-2'">
      <CardHeader><CardTitle>Active alerts</CardTitle></CardHeader>
      <CardContent>
        <p v-if="!alerts.length" class="text-sm text-muted-foreground">No active alerts.</p>
        <ul v-else class="divide-y">
          <li v-for="a in alerts.slice(0, 8)" :key="a.id" class="flex flex-wrap items-center gap-2 py-2 text-sm">
            <StateBadge :value="a.severity" />
            <!-- every active alert fires; only show the state when it differs -->
            <StateBadge v-if="a.state !== 'firing'" :value="a.state" />
            <span class="min-w-0 flex-1 truncate">{{ a.summary || a.rule_id }}</span>
            <span class="text-xs text-muted-foreground">{{ ago(a.started_at) }}</span>
          </li>
        </ul>
        <Button as-child variant="link" class="mt-2 px-0"><NuxtLink to="/alerts">All alerts</NuxtLink></Button>
      </CardContent>
    </Card>

    <Card v-if="!fleet">
      <CardHeader><CardTitle>Hardening</CardTitle></CardHeader>
      <CardContent>
        <div v-if="hard" class="flex items-center gap-4">
          <span class="text-5xl font-bold" :aria-label="`Grade ${hard.grade}`">{{ hard.grade }}</span>
          <div>
            <p class="text-xl font-semibold tabular-nums">{{ Math.round(hard.score ?? 0) }} / 100</p>
            <p class="text-xs text-muted-foreground">scanned {{ ago(hard.scanned_at) }}</p>
          </div>
        </div>
        <p v-else class="text-sm text-muted-foreground">No scan yet.</p>
        <Button as-child variant="link" class="mt-2 px-0"><NuxtLink to="/hardening">Open hardening</NuxtLink></Button>
      </CardContent>
    </Card>
  </div>

  <section v-if="!fleet" aria-label="Current metrics" class="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
    <StatCard
      label="CPU"
      :value="pct(m('cpu.total_pct'))"
      :meter="m('cpu.total_pct')"
      :warn="80"
      :crit="90"
      :sub="`iowait ${pct(m('cpu.iowait_pct'))} · steal ${pct(m('cpu.steal_pct'))}`"
    />
    <StatCard
      label="Memory"
      :value="pct(m('mem.used_pct'))"
      :meter="m('mem.used_pct')"
      :warn="85"
      :crit="95"
      :sub="`${bytes(m('mem.available_bytes'))} free · swap ${pct(m('swap.used_pct'))}`"
    />
    <StatCard
      :label="`Disk ${rootMount?.path || ''}`"
      :value="pct(rootMount?.used_pct)"
      :meter="rootMount?.used_pct"
      :warn="85"
      :crit="95"
      :sub="
        fullest && fullest !== rootMount
          ? `fullest: ${fullest.path} ${pct(fullest.used_pct)}`
          : `${bytes(rootMount?.used)} of ${bytes(rootMount?.total)}`
      "
    />
    <StatCard
      :label="`Load (1m), ${s?.system?.cpus || '?'} CPUs`"
      :value="num(m('load.1'), 2)"
      :sub="`5m ${num(m('load.5'), 2)} · 15m ${num(m('load.15'), 2)}`"
    />
    <StatCard
      label="Network in"
      :value="bytes(m('net.rx_bps_total'), '/s')"
      :sub="`out ${bytes(m('net.tx_bps_total'), '/s')}`"
    />
    <StatCard
      label="TCP connections"
      :value="num(m('net.tcp.established'))"
      :sub="`syn_recv ${num(m('net.tcp.syn_recv'))} · new ${num(m('net.new_conns_ps'), 1)}/s`"
    />
  </section>

  <Card v-if="fleet">
    <CardHeader><CardTitle>Servers</CardTitle></CardHeader>
    <CardContent>
      <LoadState
        :pending="srvPending"
        :error="srvErr"
        :empty="!servers?.length"
        empty-text="No servers enrolled. Create an enrollment token under Fleet."
      >
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Name</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>CPU</TableHead>
              <TableHead>Memory</TableHead>
              <TableHead>Disk (max)</TableHead>
              <TableHead>Next cert expiry</TableHead>
              <TableHead>Redis</TableHead>
              <TableHead>Alerts</TableHead>
              <TableHead>Score</TableHead>
              <TableHead>Last seen</TableHead>
              <TableHead>Tags</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            <TableRow v-for="x in servers" :key="x.id">
              <TableCell>
                <NuxtLink :to="`/servers/${x.id}`" class="font-medium underline-offset-4 hover:underline">
                  {{ x.name }}
                </NuxtLink>
              </TableCell>
              <TableCell><StateBadge :value="x.connected ? 'connected' : x.status || 'disconnected'" /></TableCell>
              <TableCell class="tabular-nums">{{ pct(x.latest?.cpu) }}</TableCell>
              <TableCell class="tabular-nums">{{ pct(x.latest?.mem) }}</TableCell>
              <TableCell class="tabular-nums">{{ pct(x.latest?.disk) }}</TableCell>
              <TableCell class="whitespace-nowrap tabular-nums">
                <span v-if="x.latest?.cert_days === undefined" class="text-muted-foreground">-</span>
                <span v-else :class="x.latest.cert_days < 3 ? 'text-crit' : x.latest.cert_days < 14 ? 'text-warn' : ''">
                  {{ daysLeft(x.latest.cert_days) }}
                </span>
              </TableCell>
              <TableCell class="whitespace-nowrap tabular-nums">
                <span v-if="!x.latest?.redis_total" class="text-muted-foreground">-</span>
                <span v-else :class="(x.latest.redis_up ?? 0) < x.latest.redis_total ? 'text-crit' : ''">
                  {{ x.latest.redis_up ?? 0 }}/{{ x.latest.redis_total }} up
                </span>
              </TableCell>
              <TableCell class="tabular-nums">{{ x.active_alerts || 0 }}</TableCell>
              <TableCell class="tabular-nums">{{ x.grade ? `${x.grade} · ${Math.round(x.score)}` : '-' }}</TableCell>
              <TableCell>{{ ago(x.last_seen) }}</TableCell>
              <TableCell>
                <Badge v-for="t in x.tags || []" :key="t" variant="secondary" class="mr-1">{{ t }}</Badge>
              </TableCell>
            </TableRow>
          </TableBody>
        </Table>
      </LoadState>
    </CardContent>
  </Card>
</template>
