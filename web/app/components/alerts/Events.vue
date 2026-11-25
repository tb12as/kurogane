<script setup lang="ts">
import type { components } from '~/types/api'
import type { AlertEvent } from '~/types/models'

const live = useLive()
const state = ref('all')
const period = ref('today')
const fromDate = ref('')
const toDate = ref('')
const periodOptions = [
  { value: 'today', label: 'Today' },
  { value: '1', label: 'Last 24 hours' },
  { value: '7', label: 'Last 7 days' },
  { value: '30', label: 'Last 30 days' },
  { value: 'custom', label: 'Custom' },
]
const periodNow = ref(new Date())
const periodQuery = computed(() => alertPeriod(period.value, fromDate.value, toDate.value, periodNow.value))
const query = computed(() => {
  let eventState = state.value
  if (eventState === 'all') eventState = ''
  return { ...periodQuery.value, state: eventState }
})
const periodError = computed(() => {
  if (periodQuery.value) return null
  return new Error('Invalid custom period: choose both dates with From on or before To.')
})
const { data: summary, pending: summaryPending, error: summaryError, refresh: refreshSummary } = useAsyncData(
  'alerts.summary',
  async (): Promise<components['schemas']['Summary'] | null> => {
    if (!periodQuery.value) return null
    return api.get('/alerts/events/summary', { query: periodQuery.value })
  },
  { watch: [periodQuery] },
)
const { data: channels, pending: channelsPending, error: channelsError } = useAsyncData(
  'alerts.summary.channels',
  async () => {
    if (!can('admin')) return []
    return list<components['schemas']['ChannelInfo']>(await api.get('/alerts/channels'))
  },
)
const channelOptions = computed(() => (channels.value ?? [])
  .filter(c => c.type !== 'pagerduty' && c.ready && c.name)
  .map(c => ({ value: c.name!, label: c.name! })))
const channel = ref('')
const sending = ref(false)
async function sendSummary() {
  if (!channel.value || !periodQuery.value) return
  sending.value = true
  try {
    await run(() => api.post('/alerts/events/summary/send', {
      channel: channel.value, ...periodQuery.value,
    }), 'Summary sent')
  } finally {
    sending.value = false
  }
}
const { data, pending, error, refresh } = useAsyncData(
  'alerts.events',
  async () => {
    if (!periodQuery.value) return []
    return list<AlertEvent>(await api.get('/alerts/events', { query: { ...query.value, limit: 500 } }), 'events')
  },
  { watch: [query] },
)
watch(
  [period, fromDate, toDate, () => live.tick.value.alert],
  () => { periodNow.value = new Date() },
)

async function act(e: AlertEvent, what: 'ack' | 'noise') {
  await run(() => api.post(`/alerts/events/${e.id}/${what}`), what === 'ack' ? 'Acknowledged' : 'Marked as noise')
  refresh()
  refreshSummary()
}
</script>

<template>
  <div class="flex flex-wrap items-center gap-2">
    <FormSelect v-model="period" :options="periodOptions" label="Period" />
    <template v-if="period === 'custom'">
      <Label for="events-from">From</Label>
      <Input id="events-from" v-model="fromDate" type="date" class="w-auto" />
      <Label for="events-to">To</Label>
      <Input id="events-to" v-model="toDate" type="date" class="w-auto" />
    </template>
    <div class="w-44">
      <FormSelect
        v-model="state"
        :options="[{ value: 'all', label: 'All states' }, 'open', 'firing', 'acknowledged', 'resolved']"
        label="State"
      />
    </div>
    <Button
      as="a"
      variant="outline"
      class="ml-auto"
      v-if="periodQuery"
      :href="apiUrl('/alerts/events/export', { ...query, format: 'csv' })"
      download="alerts.csv"
    >
      Export CSV
    </Button>
  </div>
  <Card>
    <CardHeader><CardTitle>Event summary</CardTitle></CardHeader>
    <CardContent class="space-y-4">
      <LoadState
        :pending="summaryPending" :error="periodError || summaryError" :empty="!summary?.total"
        empty-text="No alert events in this period. Select another period to view earlier events."
      >
        <template v-if="summary">
          <dl class="flex flex-wrap gap-6 tabular-nums">
            <div><dt class="text-sm text-muted-foreground">Total</dt><dd>{{ summary.total }}</dd></div>
            <div><dt class="text-sm text-muted-foreground">Open</dt><dd>{{ summary.open }}</dd></div>
            <div><dt class="text-sm text-muted-foreground">Noise</dt><dd>{{ summary.noise }}</dd></div>
            <div v-for="(count, severity) in summary.by_severity" :key="severity">
              <dt><StateBadge :value="String(severity)" /></dt><dd>{{ count }}</dd>
            </div>
          </dl>
          <p class="mt-4 text-sm font-medium">Top rules</p>
          <ul class="text-sm tabular-nums">
            <li v-for="rule in summary.by_rule.slice(0, 10)" :key="rule.key">{{ rule.key }}: {{ rule.count }}</li>
          </ul>
        </template>
      </LoadState>
      <div class="flex flex-wrap items-center gap-2">
        <Button
          v-if="periodQuery" as="a" variant="outline"
          :href="apiUrl('/alerts/events/summary', { ...periodQuery, format: 'csv' })"
        >Download summary CSV</Button>
        <template v-if="can('admin')">
          <LoadState
            :pending="channelsPending" :error="channelsError" :empty="!channelOptions.length"
            empty-text="No summary channels ready. Configure a chat, email or webhook channel under Channels."
          >
            <FormSelect
              v-model="channel" :options="channelOptions" label="Summary channel" placeholder="Choose channel"
            />
          </LoadState>
          <Button :disabled="sending || !channel || !periodQuery" @click="sendSummary">Send summary</Button>
        </template>
      </div>
    </CardContent>
  </Card>
  <Card>
    <CardContent>
      <LoadState
        :pending="pending" :error="periodError || error" :empty="!data?.length"
        empty-text="No alert events for this period and state. Select another period or state."
      >
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Started</TableHead>
              <TableHead>Severity</TableHead>
              <TableHead>State</TableHead>
              <TableHead>Summary</TableHead>
              <TableHead>Rule</TableHead>
              <TableHead>Server</TableHead>
              <TableHead><span class="sr-only">Actions</span></TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            <TableRow v-for="e in data" :key="e.id">
              <TableCell class="whitespace-nowrap" :title="fmtDate(e.started_at)">{{ ago(e.started_at) }}</TableCell>
              <TableCell><StateBadge :value="e.severity" /></TableCell>
              <TableCell>
                <StateBadge :value="e.state" />
                <Badge v-if="e.noise" variant="secondary" class="ml-1">noise</Badge>
              </TableCell>
              <TableCell class="max-w-md whitespace-normal">
                {{ e.summary }}
                <span v-if="e.acked_by" class="block text-xs text-muted-foreground">
                  acked by {{ e.acked_by }} {{ ago(e.acked_at) }}
                </span>
              </TableCell>
              <TableCell class="font-mono text-xs">{{ e.rule_id }}</TableCell>
              <TableCell>{{ e.server_id || '-' }}</TableCell>
              <TableCell class="whitespace-nowrap text-right">
                <template v-if="can('admin')">
                  <Button v-if="e.state === 'firing'" variant="outline" size="sm" @click="act(e, 'ack')">
                    Acknowledge
                  </Button>
                  <Button v-if="!e.noise" variant="ghost" size="sm" @click="act(e, 'noise')">Mark as noise</Button>
                  <Button as-child variant="ghost" size="sm">
                    <NuxtLink :to="{ query: { tab: 'silences', rule: e.rule_id, server: e.server_id, for: '1h' } }">
                      Silence
                    </NuxtLink>
                  </Button>
                </template>
              </TableCell>
            </TableRow>
          </TableBody>
        </Table>
      </LoadState>
    </CardContent>
  </Card>
</template>
