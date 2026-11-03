<script setup lang="ts">
import type { AlertEvent } from '~/types/models'

const live = useLive()
const state = ref('all')
const { data, pending, error, refresh } = useAsyncData(
  'alerts.events',
  async () =>
    list<AlertEvent>(
      await api.get('/alerts/events', { query: { state: state.value === 'all' ? '' : state.value, limit: 500 } }),
      'events',
    ),
  { watch: [state] },
)
watch(
  () => live.tick.value.alert,
  () => refresh(),
)

async function act(e: AlertEvent, what: 'ack' | 'noise') {
  await run(() => api.post(`/alerts/events/${e.id}/${what}`), what === 'ack' ? 'Acknowledged' : 'Marked as noise')
  refresh()
}
</script>

<template>
  <div class="flex flex-wrap items-center gap-2">
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
      :href="apiUrl('/alerts/events/export', { format: 'csv' })"
      download="alerts.csv"
    >
      Export CSV
    </Button>
  </div>
  <Card>
    <CardContent>
      <LoadState :pending="pending" :error="error" :empty="!data?.length" empty-text="No alert events for this state.">
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
