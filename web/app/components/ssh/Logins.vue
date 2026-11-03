<script setup lang="ts">
interface Login { ts: string, user: string, ip: string, success: boolean, method: string, invalid_user?: boolean }
interface Summary {
  logins: Login[] | null
  success: number
  failed: number
  top_failing_ips: { key: string, count: number }[] | null
  top_failing_users: { key: string, count: number }[] | null
}

const since = ref('24h')
const { data, pending, error } = useAsyncData(
  'ssh.logins',
  async () => (await api.get('/ssh/logins', { query: { since: since.value } })) as Summary,
  { watch: [since] },
)
const rows = computed(() => (data.value?.logins || []).slice().reverse().slice(0, 500))
</script>

<template>
  <div class="flex flex-wrap items-center gap-3">
    <div class="w-40">
      <FormSelect
        v-model="since"
        label="Period"
        :options="[
          { value: '24h', label: 'Last 24 h' },
          { value: '7d', label: 'Last 7 days' },
          { value: '30d', label: 'Last 30 days' },
        ]"
      />
    </div>
    <p v-if="data" class="text-sm text-muted-foreground">
      {{ data.success }} successful · {{ data.failed }} failed
    </p>
  </div>
  <LoadState :pending="pending" :error="error">
    <div class="mt-4 grid gap-4 lg:grid-cols-2">
      <Card v-for="t in [
        { title: 'Top failing IPs', rows: data?.top_failing_ips, mono: true },
        { title: 'Top failing users', rows: data?.top_failing_users, mono: false },
      ]" :key="t.title">
        <CardHeader><CardTitle class="text-sm">{{ t.title }}</CardTitle></CardHeader>
        <CardContent>
          <p v-if="!t.rows?.length" class="text-sm text-muted-foreground">No failed logins.</p>
          <ul class="divide-y text-sm">
            <li v-for="x in t.rows" :key="x.key" class="flex justify-between py-1.5">
              <span :class="t.mono && 'font-mono'">{{ x.key }}</span>
              <span class="tabular-nums">{{ x.count }}</span>
            </li>
          </ul>
        </CardContent>
      </Card>
    </div>
    <Table class="mt-4">
      <TableHeader>
        <TableRow>
          <TableHead>When</TableHead>
          <TableHead>User</TableHead>
          <TableHead>From</TableHead>
          <TableHead>Method</TableHead>
          <TableHead>Result</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        <TableRow v-for="(x, i) in rows" :key="i">
          <TableCell class="whitespace-nowrap">{{ fmtDate(x.ts) }}</TableCell>
          <TableCell>
            {{ x.user }}
            <span v-if="x.invalid_user" class="text-xs text-muted-foreground">(unknown user)</span>
          </TableCell>
          <TableCell class="font-mono">{{ x.ip }}</TableCell>
          <TableCell>{{ x.method || '—' }}</TableCell>
          <TableCell><StateBadge :value="x.success ? 'success' : 'failed'" /></TableCell>
        </TableRow>
        <TableEmpty v-if="!rows.length" :colspan="5">No logins in this period.</TableEmpty>
      </TableBody>
    </Table>
  </LoadState>
</template>
