<script setup lang="ts">
import { useIntervalFn } from '@vueuse/core'
import type { Cert, Line, Proc, Series, Snapshot } from '~/types/models'

const route = useRoute()
const id = computed(() => String(route.params.id))
const local = computed(() => id.value === 'local')
const live = useLive()
useHead({ title: 'Server · ServerKeeper' })

const ranges = { '1h': '', '6h': '1m', '24h': '5m', '7d': '30m' } as const
type Range = keyof typeof ranges
const range = ref<Range>('1h')

const NAMES = [
  'cpu.total_pct',
  'cpu.iowait_pct',
  'cpu.steal_pct',
  'load.1',
  'load.5',
  'load.15',
  'mem.used_pct',
  'swap.used_pct',
  'disk.used_pct',
  'diskio.read_bps',
  'diskio.write_bps',
  'net.rx_bps',
  'net.tx_bps',
  'net.tcp.established',
  'net.tcp.syn_recv',
  'net.tcp.time_wait',
  'net.tcp.close_wait',
  'net.new_conns_ps',
]

const {
  data: hist,
  pending,
  error,
  refresh,
} = useAsyncData(
  () => `hist.${id.value}.${range.value}`,
  async () => {
    const path = local.value ? '/metrics/history' : `/servers/${encodeURIComponent(id.value)}/metrics/history`
    const r = await api.get(path, { query: { names: NAMES.join(','), from: range.value, step: ranges[range.value] } })
    return list<Series>(r, 'series')
  },
  { watch: [range, id] },
)
useIntervalFn(() => refresh(), 30_000)

// fleet server: details come from /servers/{id}; local: the live snapshot
const { data: remote } = useAsyncData(
  () => `server.${id.value}`,
  async () => (local.value ? null : await api.get(`/servers/${encodeURIComponent(id.value)}`)),
  { watch: [id] },
)
const snap = computed<Snapshot | null>(() => (local.value ? live.snap.value : null))
const title = computed(() =>
  local.value
    ? snap.value?.system?.hostname || 'This server'
    : remote.value?.name || id.value,
)

const { data: sessions, error: sErr } = useAsyncData(
  () => `sessions.${id.value}`,
  async () => (local.value ? list(await api.get('/ssh/sessions'), 'sessions') : []),
  { watch: [id] },
)

function pick(metrics: string[], label?: string, names?: Record<string, string>): Line[] {
  const out: (Line & { k: string })[] = []
  for (const s of hist.value || []) {
    const i = metrics.indexOf(s.metric)
    if (i < 0) continue
    const base = names?.[s.metric] ?? s.metric
    const l = (label && s.labels?.[label]) || ''
    out.push({
      k: `${l}\u0000${String(i).padStart(2, '0')}`,
      name: [l, base].filter(Boolean).join(' '),
      data: s.points.map(p => [p[0], p[1]]),
    })
  }
  // stable order (label, then the listed metric order) so a series keeps its color between refreshes
  return out.sort((a, b) => a.k.localeCompare(b.k))
}
const charts = computed(
  () =>
    [
      {
        title: 'CPU',
        unit: 'pct',
        lines: pick(['cpu.total_pct', 'cpu.iowait_pct', 'cpu.steal_pct'], undefined, {
          'cpu.total_pct': 'total',
          'cpu.iowait_pct': 'iowait',
          'cpu.steal_pct': 'steal',
        }),
      },
      { title: 'Load average', unit: 'num', lines: pick(['load.1', 'load.5', 'load.15']) },
      {
        title: 'Memory and swap used',
        unit: 'pct',
        lines: pick(['mem.used_pct', 'swap.used_pct'], undefined, {
          'mem.used_pct': 'memory',
          'swap.used_pct': 'swap',
        }),
      },
      { title: 'Disk used per mount', unit: 'pct', lines: pick(['disk.used_pct'], 'mount', { 'disk.used_pct': '' }) },
      {
        title: 'Disk I/O',
        unit: 'bps',
        lines: pick(['diskio.read_bps', 'diskio.write_bps'], 'dev', {
          'diskio.read_bps': 'read',
          'diskio.write_bps': 'write',
        }),
      },
      {
        title: 'Network per interface',
        unit: 'bps',
        lines: pick(['net.rx_bps', 'net.tx_bps'], 'iface', { 'net.rx_bps': 'rx', 'net.tx_bps': 'tx' }),
      },
      {
        title: 'TCP connection states',
        unit: 'num',
        lines: pick(['net.tcp.established', 'net.tcp.syn_recv', 'net.tcp.time_wait', 'net.tcp.close_wait']),
      },
      { title: 'New connections per second', unit: 'num', lines: pick(['net.new_conns_ps']) },
    ] as const,
)

const procTab = ref('cpu')
const procs = computed<Proc[]>(() => (procTab.value === 'cpu' ? snap.value?.top_cpu : snap.value?.top_mem) || [])

// soonest expiry first; unreadable files last
const certs = computed<Cert[]>(() =>
  [...(snap.value?.certs || [])].sort(
    (a, b) => Number(!!a.error) - Number(!!b.error) || a.days_left - b.days_left || a.name.localeCompare(b.name),
  ),
)
const rescanning = ref(false)
async function rescan() {
  rescanning.value = true
  // the next live snapshot (within one collection interval) carries the new scan
  await run(() => api.post('/certs/rescan'), 'Certificates rescanned')
  rescanning.value = false
}
function certNote(c: Cert) {
  if (c.error) return c.error
  const n: string[] = []
  if (c.stale) n.push(`port ${c.served_port} serves an older copy (until ${when(c.served_not_after)?.toLocaleDateString() ?? '-'}): reload the web server`)
  if (c.key_type === 'RSA' && (c.key_bits || 0) < 2048) n.push(`RSA ${c.key_bits} bits`)
  if (/sha1|md5/i.test(c.sig_alg || '')) n.push(`signed with ${c.sig_alg}`)
  return n.join(' · ')
}

async function kill(pid: number) {
  await run(() => api.del(`/ssh/sessions/${pid}`), `Session ${pid} killed`)
  refreshNuxtData(`sessions.${id.value}`)
}
</script>

<template>
  <div class="flex flex-wrap items-center justify-between gap-3">
    <div>
      <h1 class="text-2xl font-semibold">{{ title }}</h1>
      <p v-if="snap?.system" class="text-sm text-muted-foreground">
        {{ snap.system.os }} · {{ snap.system.kernel }} · {{ snap.system.cpus }} CPUs ·
        {{ bytes(snap.system.mem_total) }} RAM
      </p>
      <p v-else-if="remote" class="text-sm text-muted-foreground">
        {{ remote.os }} · {{ remote.kernel }} · agent {{ remote.agent_version }} · last seen {{ ago(remote.last_seen) }}
      </p>
    </div>
    <Tabs v-model="range">
      <TabsList aria-label="Time range">
        <TabsTrigger v-for="(_, r) in ranges" :key="r" :value="r">{{ r }}</TabsTrigger>
      </TabsList>
    </Tabs>
  </div>

  <Alert v-if="error" variant="destructive">
    <AlertDescription>{{ errMsg(error) }}</AlertDescription>
  </Alert>

  <section aria-label="Charts" class="grid gap-4 lg:grid-cols-2">
    <MetricChart
      v-for="c in charts"
      :key="c.title"
      :title="c.title"
      :unit="c.unit"
      :lines="c.lines"
      :loading="pending"
    />
  </section>

  <!-- services and processes come from the local snapshot; the central server keeps only time series -->
  <div v-if="local" class="grid gap-4 lg:grid-cols-2">
    <Card>
      <CardHeader><CardTitle>Services</CardTitle></CardHeader>
      <CardContent>
        <p v-if="!snap?.services?.length" class="text-sm text-muted-foreground">
          No watched services. Add units to collector.watch_services.
        </p>
        <ul v-else class="divide-y text-sm">
          <li v-for="x in snap.services" :key="x.unit" class="flex items-center justify-between py-2">
            <span class="font-mono">{{ x.unit }}</span>
            <span class="flex items-center gap-2">
              <span class="text-xs text-muted-foreground">{{ x.sub }}</span>
              <StateBadge :value="x.active" />
            </span>
          </li>
        </ul>
      </CardContent>
    </Card>

    <Card>
      <CardHeader class="flex flex-row items-center justify-between">
        <CardTitle>Top processes</CardTitle>
        <Tabs v-model="procTab">
          <TabsList aria-label="Sort processes by">
            <TabsTrigger value="cpu">CPU</TabsTrigger>
            <TabsTrigger value="mem">Memory</TabsTrigger>
          </TabsList>
        </Tabs>
      </CardHeader>
      <CardContent>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>PID</TableHead>
              <TableHead>Name</TableHead>
              <TableHead>User</TableHead>
              <TableHead class="text-right">CPU</TableHead>
              <TableHead class="text-right">RSS</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            <TableRow v-for="p in procs" :key="p.pid">
              <TableCell class="tabular-nums">{{ p.pid }}</TableCell>
              <TableCell class="max-w-48 truncate" :title="p.cmd">{{ p.name }}</TableCell>
              <TableCell>{{ p.user }}</TableCell>
              <TableCell class="text-right tabular-nums">{{ pct(p.cpu_pct) }}</TableCell>
              <TableCell class="text-right tabular-nums">{{ bytes(p.rss) }}</TableCell>
            </TableRow>
            <TableEmpty v-if="!procs.length" :colspan="5">No process data yet.</TableEmpty>
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  </div>

  <Card v-if="local">
    <CardHeader class="flex flex-row items-center justify-between">
      <CardTitle>TLS certificates</CardTitle>
      <Button variant="outline" size="sm" :disabled="rescanning" @click="rescan">
        {{ rescanning ? 'Scanning…' : 'Rescan' }}
      </Button>
    </CardHeader>
    <CardContent>
      <p v-if="!certs.length" class="text-sm text-muted-foreground">
        No certificates found. Let's Encrypt and nginx ssl_certificate files are found automatically; add other PEM
        files to collector.certs.paths.
      </p>
      <Table v-else>
        <TableHeader>
          <TableRow>
            <TableHead>Name</TableHead>
            <TableHead>Expires</TableHead>
            <TableHead>Issuer</TableHead>
            <TableHead>Served</TableHead>
            <TableHead class="text-right">State</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          <TableRow v-for="c in certs" :key="c.name">
            <TableCell class="max-w-72">
              <div class="truncate font-mono" :title="c.dns_names?.join(', ')">{{ c.name }}</div>
              <div class="truncate text-xs text-muted-foreground" :title="c.path">{{ c.origin }} · {{ c.path || 'no file found' }}</div>
              <div v-if="certNote(c)" class="text-xs whitespace-normal break-words text-warn">{{ certNote(c) }}</div>
            </TableCell>
            <TableCell class="whitespace-nowrap tabular-nums">
              <div>{{ c.error ? '-' : daysLeft(c.days_left) }}</div>
              <div class="text-xs text-muted-foreground">{{ c.error ? '' : fmtDate(c.not_after) }}</div>
            </TableCell>
            <TableCell class="max-w-48 truncate" :title="c.issuer">{{ c.issuer || '-' }}</TableCell>
            <TableCell class="tabular-nums">{{ c.served_port ? `:${c.served_port}` : '-' }}</TableCell>
            <TableCell class="text-right"><StateBadge :value="certState(c)" /></TableCell>
          </TableRow>
        </TableBody>
      </Table>
    </CardContent>
  </Card>

  <Card v-if="local">
    <CardHeader><CardTitle>SSH sessions</CardTitle></CardHeader>
    <CardContent><LoadState :error="sErr"><SshSessionsTable :rows="sessions || []" @kill="kill" /></LoadState></CardContent>
  </Card>
</template>
