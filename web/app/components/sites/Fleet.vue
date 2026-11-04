<script setup lang="ts">
import { toast } from 'vue-sonner'
import type { FleetSite, FleetWebServer } from '~/types/models'

const writer = computed(() => can('web:write'))
const q = ref('')
const query = ref('')
let timer: ReturnType<typeof setTimeout> | undefined
watch(q, v => {
  clearTimeout(timer)
  timer = setTimeout(() => (query.value = v.trim()), 250)
})
const { data, pending, error, refresh } = useAsyncData(
  'fleet.sites',
  async () => (await api.get('/fleet/sites', { query: { q: query.value } })) as { servers: FleetWebServer[]; sites: FleetSite[] },
  { watch: [query] },
)
const broken = computed(() => (data.value?.servers || []).filter(w => !w.config_ok))

// remote toggles run as a fleet op: the agent does the dry run checks, test, reload, probe and rollback itself
const target = ref<FleetSite | null>(null)
const open = ref(false)
function ask(x: FleetSite) {
  target.value = x
  open.value = true
}
const action = computed(() => (target.value?.enabled ? 'Disable' : 'Enable'))
async function preview() {
  const x = target.value!
  return {
    impact: [
      `${action.value}s ${(x.names || [x.name]).join(', ')} on ${x.server_name} (${x.file}).`,
      'Queued as a fleet operation. The agent checks the configuration, reloads and re-probes its other sites, ' +
        'and undoes the change by itself if anything fails.',
      'Offline servers apply it when they reconnect; the result appears under Fleet → Operations.',
    ],
  }
}
async function apply() {
  const x = target.value!
  return api.post('/fleet/sites/apply', { server: x.server_id, id: x.id, enabled: !x.enabled })
}
function done() {
  toast.success('Queued: see Fleet → Operations for the result')
  setTimeout(() => refresh(), 3000)
}
</script>

<template>
  <div class="space-y-4">
    <Alert v-for="w in broken" :key="w.server_id + w.kind" variant="destructive">
      <AlertTitle>{{ w.kind }} configuration test fails on {{ w.server_name }}</AlertTitle>
      <AlertDescription>{{ w.config_error }}</AlertDescription>
    </Alert>
    <Input v-model="q" placeholder="Which server hosts… (name, e.g. shop.example.org)" class="max-w-md" aria-label="Search sites" />
    <Card>
      <CardContent>
        <LoadState
          :pending="pending"
          :error="error"
          :empty="!data?.sites.length"
          :empty-text="query ? `No site matches “${query}”.` : 'No agent has reported web sites yet.'"
        >
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Site</TableHead>
                <TableHead>Server</TableHead>
                <TableHead>Ports</TableHead>
                <TableHead>Certificate</TableHead>
                <TableHead class="text-right">Enabled</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              <TableRow v-for="x in data?.sites" :key="x.server_id + x.id">
                <TableCell class="max-w-80">
                  <div class="truncate font-mono" :title="(x.names || []).join(' ')">{{ x.name }}</div>
                  <div class="truncate text-xs text-muted-foreground">{{ x.kind }} · {{ x.file }}</div>
                </TableCell>
                <TableCell>
                  <NuxtLink :to="`/servers/${x.server_id}`" class="underline-offset-4 hover:underline">{{ x.server_name }}</NuxtLink>
                </TableCell>
                <TableCell class="tabular-nums">{{ (x.ports || []).join(', ') }}{{ x.tls ? ' (TLS)' : '' }}</TableCell>
                <TableCell class="whitespace-nowrap tabular-nums">
                  <span
                    v-if="x.cert_days !== undefined && x.cert_days !== null"
                    :class="x.cert_days < 3 ? 'text-crit' : x.cert_days < 14 ? 'text-warn' : ''"
                  >
                    {{ daysLeft(x.cert_days) }}
                  </span>
                  <span v-else class="text-muted-foreground">-</span>
                </TableCell>
                <TableCell class="text-right">
                  <div class="flex items-center justify-end gap-2">
                    <span v-if="!x.toggleable" class="text-xs text-muted-foreground" :title="x.no_toggle">fixed</span>
                    <Switch
                      :model-value="x.enabled"
                      :disabled="!writer || !x.toggleable"
                      :aria-label="`${x.enabled ? 'Disable' : 'Enable'} ${x.name} on ${x.server_name}`"
                      :title="x.no_toggle || ''"
                      @update:model-value="ask(x)"
                    />
                  </div>
                </TableCell>
              </TableRow>
            </TableBody>
          </Table>
        </LoadState>
      </CardContent>
    </Card>
  </div>

  <RiskDialog
    v-model:open="open"
    :title="`${action} ${target?.name} on ${target?.server_name}`"
    :confirm="`Queue ${action.toLowerCase()}`"
    :preview="preview"
    :apply="apply"
    @done="done"
  />
</template>
