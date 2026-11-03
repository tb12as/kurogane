<script setup lang="ts">
import { toast } from 'vue-sonner'
import type { Ignore } from '~/types/models'

useHead({ title: 'Hardening · ServerKeeper' })
const tab = useTab('results')
const live = useLive()

interface Result {
  id: string
  title: string
  status: string
  severity: string
  category: string
  rationale: string
  remediation: string
  cis: string
  evidence: string
  fixable: boolean
}

const { data: checks } = useAsyncData('harden.checks', async () => {
  const m: Record<string, any> = {}
  for (const c of list<any>(await api.get('/harden/checks').catch(() => []), 'checks')) m[c.id ?? c.check_id] = c
  return m
})
const {
  data: scan,
  pending,
  error,
  refresh,
} = useAsyncData('harden.scan', async () => {
  try {
    return await api.get('/harden/scans/latest')
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) return null
    throw e
  }
})
watch(
  () => live.tick.value.harden,
  () => refresh(),
)

const results = computed<Result[]>(() =>
  list<any>(scan.value?.results, 'results').map(r => {
    const id = r.check_id ?? r.id
    const c = checks.value?.[id] || {}
    const g = (k: string) => r[k] ?? c[k] ?? ''
    return {
      id,
      title: g('title') || g('name') || id,
      status: String(r.status ?? ''),
      severity: String(g('severity')).toLowerCase(),
      category: g('category'),
      rationale: g('rationale'),
      remediation: g('remediation'),
      cis: g('cis') || g('cis_id'),
      evidence: typeof r.evidence === 'string' ? r.evidence : r.evidence ? JSON.stringify(r.evidence) : '',
      fixable: Boolean(r.fixable ?? c.fixable ?? c.auto_fix ?? false),
    }
  }),
)

const f = reactive({ status: 'all', severity: 'all', category: 'all', q: '' })
const allLabel = { status: 'All statuses', severity: 'All severities', category: 'All categories' }
const opts = (k: 'status' | 'severity' | 'category') => [
  { value: 'all', label: allLabel[k] },
  ...[...new Set(results.value.map(r => r[k]).filter(Boolean))].map(v => ({ value: v, label: v })),
]
const sevRank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 }
const shown = computed(() =>
  results.value
    .filter(
      r =>
        (f.status === 'all' || r.status === f.status) &&
        (f.severity === 'all' || r.severity === f.severity) &&
        (f.category === 'all' || r.category === f.category) &&
        (!f.q || (r.id + r.title).toLowerCase().includes(f.q.toLowerCase())),
    )
    .sort(
      (a, b) =>
        Number(a.status === 'pass') - Number(b.status === 'pass') ||
        (sevRank[a.severity] ?? 9) - (sevRank[b.severity] ?? 9),
    ),
)
const counts = computed(() => {
  const c: Record<string, number> = {}
  for (const r of results.value) c[r.status] = (c[r.status] || 0) + 1
  return c
})
const expanded = ref<Record<string, boolean>>({})

const scanning = ref(false)
async function runScan() {
  scanning.value = true
  const r = await run(() => api.post('/harden/scans'), 'Scan finished')
  scanning.value = false
  if (r) scan.value = r
}

// fix: single check or all failing at/above a severity
const fixOpen = ref(false)
const fixReq = ref<Record<string, unknown>>({})
const fixTitle = ref('')
const fixImpact = ref<string[]>([])
const fixAllSev = ref('high')
function openFix(r?: Result) {
  fixReq.value = r ? { check_id: r.id } : { all: true, severity: fixAllSev.value }
  fixTitle.value = r ? `Fix ${r.id}: ${r.title}` : `Fix all failing checks with severity ${fixAllSev.value} or higher`
  fixImpact.value = [
    'A backup is taken first; you can revert this fix from Fix history.',
    'The check is re-run after applying to verify the result.',
  ]
  if (!r || /firewall/i.test(r.category))
    fixImpact.value.push(
      'Firewall fixes block inbound ports that are not allowed. ' +
        'Make sure your SSH port and every port your apps serve are allowed.',
    )
  if (!r || /ssh/i.test(r.category))
    fixImpact.value.push(
      'SSH fixes go through safe-apply: confirm the pending change within the rollback timer or it is undone.',
    )
  fixOpen.value = true
}
// POST /harden/fixes always answers FixResult[]: {check_id, diff: {diff, note}, verify, skipped, error}
interface FixResult {
  check_id: string
  diff?: { diff?: string, note?: string }
  verify?: { status: string }
  skipped?: string
  error?: string
}
async function fixPreview() {
  const rs = list<FixResult>(await api.post('/harden/fixes', { ...fixReq.value, dry_run: true }))
  const todo = rs.filter(x => !x.skipped && !x.error)
  return {
    diff: todo.map(x => (rs.length > 1 ? `# ${x.check_id}\n` : '') + (x.diff?.diff || '')).join('\n'),
    impact: todo.map(x => x.diff?.note || '').filter(Boolean),
    warnings: rs.filter(x => x.skipped || x.error).map(x => `${x.check_id}: ${x.error || x.skipped}`),
  }
}
function fixDone(r: unknown) {
  const rs = list<FixResult>(r)
  const failed = rs.filter(x => x.error)
  if (failed.length) toast.error(failed.map(x => `${x.check_id}: ${x.error}`).join('\n'))
  const ok = rs.filter(x => x.verify)
  if (ok.length) toast.success(ok.map(x => `${x.check_id} fixed, check now ${x.verify!.status}`).join('\n'))
  live.tick.value.ssh++
  refresh()
  refreshNuxtData('harden.fixes')
}

// ignore with mandatory reason (accepted risk)
const ign = ref<Result | null>(null)
const reason = ref('')
async function submitIgnore() {
  if (
    (await run(
      () => api.post('/harden/ignores', { check_id: ign.value!.id, reason: reason.value.trim() }),
      'Check ignored',
    )) === undefined
  )
    return
  ign.value = null
  reason.value = ''
  refreshIgnores()
  refresh()
}
const {
  data: ignores,
  pending: ignPending,
  error: ignErr,
  refresh: refreshIgnores,
} = useAsyncData('harden.ignores', async () => list<Ignore>(await api.get('/harden/ignores'), 'ignores'))
async function unignore(i: Ignore) {
  await run(() => api.del(`/harden/ignores/${encodeURIComponent(i.id || i.check_id)}`), 'Ignore removed')
  refreshIgnores()
}
</script>

<template>
  <div class="flex flex-wrap items-center gap-3">
    <h1 class="text-2xl font-semibold">Hardening</h1>
    <div class="ml-auto flex flex-wrap gap-2">
      <template v-if="scan?.id">
        <Button
          v-for="fmt in ['json', 'md', 'pdf']"
          :key="fmt"
          as="a"
          variant="outline"
          size="sm"
          :href="apiUrl(`/harden/scans/${scan.id}/report`, { format: fmt })"
          :download="`hardening-${scan.id}.${fmt}`"
        >
          Report {{ fmt.toUpperCase() }}
        </Button>
      </template>
      <Button v-if="can('harden:write')" :disabled="scanning" @click="runScan">
        {{ scanning ? 'Scanning…' : 'Run scan' }}
      </Button>
    </div>
  </div>

  <LoadState :pending="pending" :error="error">
    <section v-if="scan" aria-label="Score" class="grid grid-cols-2 gap-3 sm:grid-cols-4">
      <Card class="py-4">
        <CardContent class="flex items-center gap-3 px-4">
          <span class="text-4xl font-bold" :aria-label="`Grade ${scan?.grade}`">{{ scan?.grade }}</span>
          <div>
            <p class="text-lg font-semibold tabular-nums">{{ Math.round(scan?.score ?? 0) }} / 100</p>
            <p class="text-xs text-muted-foreground">{{ ago(scan?.finished_at || scan?.started_at) }}</p>
          </div>
        </CardContent>
      </Card>
      <StatCard label="Passed" :value="String(counts.pass || 0)" />
      <StatCard label="Failed" :value="String(counts.fail || 0)" />
      <StatCard
        label="Ignored / not applicable"
        :value="String((counts.ignored || 0) + (counts.na || 0) + (counts.not_applicable || 0) + (counts.skip || 0))"
      />
    </section>
  </LoadState>

  <Tabs v-model="tab">
    <TabsList>
      <TabsTrigger value="results">Results</TabsTrigger>
      <TabsTrigger value="fixes">Fix history</TabsTrigger>
      <TabsTrigger value="ignores">Ignored checks</TabsTrigger>
    </TabsList>

    <TabsContent value="results" class="space-y-3">
      <div v-if="scan" class="grid grid-cols-2 gap-2 sm:flex sm:flex-wrap sm:items-end">
        <Input v-model="f.q" placeholder="Search checks" aria-label="Search checks" class="col-span-2 sm:w-56" />
        <div class="sm:w-36"><FormSelect v-model="f.status" :options="opts('status')" label="Status" /></div>
        <div class="sm:w-36"><FormSelect v-model="f.severity" :options="opts('severity')" label="Severity" /></div>
        <div class="sm:w-40"><FormSelect v-model="f.category" :options="opts('category')" label="Category" /></div>
        <div v-if="can('harden:write')" class="col-span-2 flex gap-2 sm:ml-auto">
          <div class="w-40">
            <FormSelect
              v-model="fixAllSev"
              :options="[
                { value: 'critical', label: 'Critical only' },
                { value: 'high', label: 'High and above' },
                { value: 'medium', label: 'Medium and above' },
                { value: 'low', label: 'All severities' },
              ]"
              label="Minimum severity to fix"
            />
          </div>
          <Button variant="outline" :disabled="!counts.fail" @click="openFix()">Fix all failing</Button>
        </div>
      </div>
      <Card>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead class="w-8"><span class="sr-only">Details</span></TableHead>
                <TableHead>Check</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Severity</TableHead>
                <TableHead>Category</TableHead>
                <TableHead>CIS</TableHead>
                <TableHead><span class="sr-only">Actions</span></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              <template v-for="r in shown" :key="r.id">
                <TableRow>
                  <TableCell>
                    <Button
                      variant="ghost"
                      size="icon-xs"
                      :aria-expanded="!!expanded[r.id]"
                      :aria-controls="`d-${r.id}`"
                      :aria-label="`Details for ${r.id}`"
                      @click="expanded[r.id] = !expanded[r.id]"
                    >
                      {{ expanded[r.id] ? '−' : '+' }}
                    </Button>
                  </TableCell>
                  <TableCell>
                    <div class="font-medium">{{ r.title }}</div>
                    <div class="font-mono text-xs text-muted-foreground">{{ r.id }}</div>
                  </TableCell>
                  <TableCell><StateBadge :value="r.status" /></TableCell>
                  <TableCell><StateBadge :value="r.severity" /></TableCell>
                  <TableCell>{{ r.category }}</TableCell>
                  <TableCell class="font-mono text-xs">{{ r.cis || '-' }}</TableCell>
                  <TableCell class="whitespace-nowrap text-right">
                    <template v-if="can('harden:write') && r.status !== 'pass' && r.status !== 'ignored'">
                      <Button v-if="r.fixable" variant="outline" size="sm" @click="openFix(r)">Fix</Button>
                      <Button variant="ghost" size="sm" @click="ign = r">Ignore</Button>
                    </template>
                  </TableCell>
                </TableRow>
                <TableRow v-if="expanded[r.id]" :id="`d-${r.id}`" class="bg-muted/30 hover:bg-muted/30">
                  <TableCell colspan="7" class="whitespace-normal">
                    <dl class="grid gap-3 py-2 text-sm md:grid-cols-3">
                      <div>
                        <dt class="font-medium">Why it matters</dt>
                        <dd class="text-muted-foreground">{{ r.rationale || '-' }}</dd>
                      </div>
                      <div>
                        <dt class="font-medium">How to fix</dt>
                        <dd class="text-muted-foreground">{{ r.remediation || '-' }}</dd>
                      </div>
                      <div>
                        <dt class="font-medium">Evidence</dt>
                        <dd class="break-all font-mono text-xs text-muted-foreground">{{ r.evidence || '-' }}</dd>
                      </div>
                    </dl>
                  </TableCell>
                </TableRow>
              </template>
              <TableEmpty v-if="!shown.length" :colspan="7">
                <template v-if="scan">No checks match these filters.</template>
                <template v-else>No scan yet. Run a scan to grade this server against the hardening checks.</template>
              </TableEmpty>
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </TabsContent>

    <TabsContent value="fixes"><HardenFixes /></TabsContent>

    <TabsContent value="ignores">
      <Card>
        <CardContent>
          <LoadState
            :pending="ignPending"
            :error="ignErr"
            :empty="!ignores?.length"
            empty-text="No ignored checks. Ignore a check from its row in Results to drop it from the score."
          >
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Check</TableHead>
                  <TableHead>Reason</TableHead>
                  <TableHead>By</TableHead>
                  <TableHead>When</TableHead>
                  <TableHead><span class="sr-only">Actions</span></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                <TableRow v-for="i in ignores" :key="i.check_id">
                  <TableCell class="font-mono">{{ i.check_id }}</TableCell>
                  <TableCell class="whitespace-normal">{{ i.reason }}</TableCell>
                  <TableCell>{{ i.created_by }}</TableCell>
                  <TableCell>{{ fmtDate(i.created_at) }}</TableCell>
                  <TableCell class="text-right">
                    <ConfirmButton
                      v-if="can('harden:write')"
                      :title="`Stop ignoring ${i.check_id}?`"
                      confirm="Remove ignore"
                      description="The check counts toward the score again from the next scan."
                      :action="() => unignore(i)"
                    >
                      Remove
                    </ConfirmButton>
                  </TableCell>
                </TableRow>
              </TableBody>
            </Table>
          </LoadState>
        </CardContent>
      </Card>
    </TabsContent>
  </Tabs>

  <RiskDialog
    v-model:open="fixOpen"
    :title="fixTitle"
    confirm="Apply fix"
    :impact="fixImpact"
    wide
    :preview="fixPreview"
    :apply="() => api.post('/harden/fixes', { ...fixReq, dry_run: false, confirm: true })"
    @done="fixDone"
  />

  <Dialog
    :open="!!ign"
    @update:open="
      (v: boolean) => {
        if (!v) ign = null
      }
    "
  >
    <DialogContent>
      <DialogHeader>
        <DialogTitle>Ignore {{ ign?.id }}</DialogTitle>
        <DialogDescription>
          Ignored checks are excluded from the score. Record why this risk is accepted; it is shown in reports.
        </DialogDescription>
      </DialogHeader>
      <form class="space-y-3" @submit.prevent="submitIgnore">
        <Label for="reason">Reason (required)</Label>
        <Textarea
          id="reason"
          v-model="reason"
          required
          minlength="5"
          placeholder="Port 22 required by provider console"
        />
        <DialogFooter><Button type="submit" :disabled="reason.trim().length < 5">Ignore check</Button></DialogFooter>
      </form>
    </DialogContent>
  </Dialog>
</template>
