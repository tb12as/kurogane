<script setup lang="ts">
import { toast } from 'vue-sonner'
import type { Preview, Site, SiteInventory, WebServer } from '~/types/models'

const live = useLive()
const writer = computed(() => can('web:write'))
const { data, pending, error, refresh } = useAsyncData('sites.inventory', async () => (await api.get('/sites')) as SiteInventory)
watch(
  () => live.tick.value.sites,
  () => refresh(),
)

const q = ref('')
const shown = computed(() => {
  const s = q.value.trim().toLowerCase()
  return (data.value?.sites || []).filter(
    x => !s || x.id.toLowerCase().includes(s) || (x.names || [x.name]).some(n => n.toLowerCase().includes(s)),
  )
})
const byServer = computed(() =>
  (data.value?.servers || []).map(w => ({ w, sites: shown.value.filter(x => x.kind === w.kind) })),
)

function ports(x: Site) {
  return [...new Set(x.listen.map(l => `${l.port}${l.tls ? ' TLS' : ''}`))].join(', ')
}
function serves(x: Site) {
  if (x.upstreams?.length) return '→ ' + x.upstreams.join(', ')
  return x.root || '-'
}

// toggle: the switch opens the dry-run dialog; the inventory only changes after the apply
const target = ref<Site | null>(null)
const open = ref(false)
function ask(x: Site) {
  target.value = x
  open.value = true
}
const action = computed(() => (target.value?.enabled ? 'Disable' : 'Enable'))
async function preview() {
  const x = target.value!
  return (await api.post('/sites/plan', { id: x.id, enabled: !x.enabled })) as Preview
}
async function apply() {
  const x = target.value!
  return api.post('/sites/apply', { id: x.id, enabled: !x.enabled })
}
function done() {
  toast.success(`${target.value?.name} ${target.value?.enabled ? 'disabled' : 'enabled'}`)
  refresh()
  refreshNuxtData('sites.changes')
}

const busy = ref('')
async function rescan() {
  busy.value = 'rescan'
  const r = await run(() => api.post('/sites/rescan'), 'Configuration re-read and tested')
  if (r) data.value = r as SiteInventory
  busy.value = ''
}
async function reload(w: WebServer) {
  busy.value = w.kind
  await run(() => api.post('/web/{server}/reload', undefined, { path: { server: w.kind } }), `${w.unit} reloaded`)
  busy.value = ''
}

// raw file viewer (web:write: configs can hold secrets)
const fileOpen = ref(false)
const file = ref<{ file?: string; content?: string } | null>(null)
async function view(x: Site) {
  file.value = null
  fileOpen.value = true
  file.value = (await run(() => api.get('/sites/config', { query: { id: x.id } }))) || { file: x.file, content: '' }
}
</script>

<template>
  <LoadState :pending="pending" :error="error">
    <Alert v-if="data && !data.enabled">
      <AlertTitle>Site management is off</AlertTitle>
      <AlertDescription>Set <code>web.enabled: true</code> in the agent config and restart the agent.</AlertDescription>
    </Alert>
    <p v-else-if="data && !data.servers.length" class="py-6 text-center text-sm text-muted-foreground">
      No nginx or Apache configuration found on this server.
    </p>
    <div v-else class="space-y-4">
      <div class="flex flex-wrap items-center gap-2">
        <Input v-model="q" placeholder="Filter by name or file" class="max-w-xs" aria-label="Filter sites" />
        <span class="text-xs text-muted-foreground">Read {{ ago(data?.scanned_at) }}</span>
        <Button v-if="writer" variant="outline" size="sm" class="ml-auto" :disabled="!!busy" @click="rescan">
          {{ busy === 'rescan' ? 'Testing…' : 'Re-read and test' }}
        </Button>
      </div>

      <Card v-for="{ w, sites } in byServer" :key="w.kind">
        <CardHeader class="flex flex-row flex-wrap items-center justify-between gap-2">
          <div>
            <CardTitle class="capitalize">{{ w.kind }}</CardTitle>
            <p class="text-xs text-muted-foreground">
              {{ w.version || 'version unknown' }} · unit {{ w.unit }} · {{ w.files }} config file(s) · tested
              {{ ago(w.tested_at) }}
            </p>
          </div>
          <div class="flex items-center gap-2">
            <StateBadge :value="w.active ? 'active' : 'down'" />
            <StateBadge :value="w.config_ok ? 'config ok' : 'config fails'" />
            <Button v-if="writer" variant="outline" size="sm" :disabled="!!busy || !w.config_ok" @click="reload(w)">
              {{ busy === w.kind ? 'Reloading…' : 'Reload' }}
            </Button>
          </div>
        </CardHeader>
        <CardContent class="space-y-3">
          <Alert v-if="!w.config_ok && w.tested_at" variant="destructive">
            <AlertTitle>Configuration test fails</AlertTitle>
            <AlertDescription>
              {{ w.config_error }}. The running server is unaffected, but the next reload or reboot fails. Site changes
              are refused until this is fixed.
            </AlertDescription>
          </Alert>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Site</TableHead>
                <TableHead>Ports</TableHead>
                <TableHead>Serves</TableHead>
                <TableHead>Certificate</TableHead>
                <TableHead class="text-right">Enabled</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              <TableRow v-for="x in sites" :key="x.id">
                <TableCell class="max-w-80">
                  <div class="flex items-center gap-2">
                    <span class="truncate font-mono" :title="(x.names || []).join(' ')">{{ x.name }}</span>
                    <span v-if="x.name === '_'" class="text-xs text-muted-foreground">catch-all</span>
                    <Badge v-if="x.default" variant="secondary">default</Badge>
                    <Badge v-if="x.php" variant="secondary">PHP</Badge>
                  </div>
                  <div v-if="(x.names?.length || 0) > 1" class="truncate text-xs text-muted-foreground">
                    also {{ x.names!.filter(n => n !== x.name).join(', ') }}
                  </div>
                  <button
                    v-if="writer"
                    type="button"
                    class="truncate text-left text-xs text-muted-foreground underline-offset-4 hover:underline"
                    :title="`View ${x.file}`"
                    @click="view(x)"
                  >
                    {{ x.file }}:{{ x.line }}
                  </button>
                  <div v-else class="truncate text-xs text-muted-foreground">{{ x.file }}:{{ x.line }}</div>
                </TableCell>
                <TableCell class="whitespace-nowrap tabular-nums">{{ ports(x) }}</TableCell>
                <TableCell class="max-w-56 truncate font-mono text-xs" :title="serves(x)">{{ serves(x) }}</TableCell>
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
                    <span v-if="!x.toggle" class="max-w-48 text-xs text-muted-foreground" :title="x.no_toggle">
                      {{ x.enabled ? 'on' : 'off' }} · fixed
                    </span>
                    <Switch
                      :model-value="x.enabled"
                      :disabled="!writer || !x.toggle || !w.config_ok"
                      :aria-label="`${x.enabled ? 'Disable' : 'Enable'} ${x.name}`"
                      :title="x.no_toggle || (!w.config_ok ? 'Fix the configuration test first' : '')"
                      @update:model-value="ask(x)"
                    />
                  </div>
                </TableCell>
              </TableRow>
              <TableEmpty v-if="!sites.length" :colspan="5">No sites match.</TableEmpty>
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  </LoadState>

  <RiskDialog
    v-model:open="open"
    :title="`${action} ${target?.name}`"
    :confirm="action"
    :preview="preview"
    :apply="apply"
    @done="done"
  />

  <Dialog v-model:open="fileOpen">
    <DialogScrollContent class="sm:max-w-3xl">
      <DialogHeader>
        <DialogTitle class="break-all font-mono text-base">{{ file?.file || 'Loading…' }}</DialogTitle>
        <DialogDescription>Read-only. ServerKeeper never edits site files; it only links, unlinks or renames them.</DialogDescription>
      </DialogHeader>
      <pre class="max-h-[60vh] overflow-auto rounded-md bg-muted p-3 text-xs">{{ file?.content }}</pre>
    </DialogScrollContent>
  </Dialog>
</template>
