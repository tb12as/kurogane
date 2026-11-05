<script setup lang="ts">
import { BookOpen, Info } from '@lucide/vue'
import type { AlertRule, Channel, MetricDef } from '~/types/models'

const { data, pending, error, refresh } = useAsyncData('alerts.rules', async () =>
  list<AlertRule>(await api.get('/alerts/rules'), 'rules'),
)
const { data: channels } = useAsyncData('alerts.channels', async () =>
  list<Channel>(await api.get('/alerts/channels'), 'channels'),
)
const { data: metrics, refresh: refreshMetrics } = useAsyncData('alerts.metrics', async () =>
  list<MetricDef>(await api.get('/alerts/metrics')),
)
const admin = computed(() => can('admin'))
const byName = computed(() => Object.fromEntries((metrics.value || []).map(m => [m.name, m])))

const open = ref(false)
const editing = ref<AlertRule | null>(null)
function openRule(r?: AlertRule) {
  editing.value = r ?? null
  refreshMetrics() // fresh "Now:" values in the builder
  open.value = true
}
async function toggle(r: AlertRule) {
  const msg = r.enabled ? 'Rule disabled' : 'Rule enabled'
  await run(() => api.put(`/alerts/rules/${encodeURIComponent(r.id)}`, { enabled: !r.enabled }), msg)
  refresh()
}
async function del(r: AlertRule) {
  await run(() => api.del(`/alerts/rules/${encodeURIComponent(r.id)}`), 'Rule deleted')
  refresh()
}
function ruleMetrics(r: AlertRule): MetricDef[] {
  const seen = new Set<string>()
  const out: MetricDef[] = []
  for (const c of r.conditions?.items || []) {
    const d = byName.value[c.metric]
    if (d && !seen.has(d.name)) {
      seen.add(d.name)
      out.push(d)
    }
  }
  return out
}

// metrics reference
const showRef = ref(false)
const q = ref('')
const refGroups = computed(() => {
  const s = q.value.trim().toLowerCase()
  const out: { name: string; items: MetricDef[] }[] = []
  for (const m of metrics.value || []) {
    if (s && ![m.title, m.name, m.group, m.description].some(x => x.toLowerCase().includes(s))) continue
    let g = out.find(x => x.name === m.group)
    if (!g) out.push((g = { name: m.group, items: [] }))
    g.items.push(m)
  }
  return out
})
function liveSummary(m: MetricDef) {
  if (!m.live.length) return m.computed ? 'computed when rules run' : '-'
  const key = m.labels?.[0]
  const parts = m.live.slice(0, 3).map(s => {
    const v = m.unit === 'bool' ? (m.states?.[String(s.value)] ?? numText(s.value)) : formatValue(m, Math.round(s.value * 10) / 10)
    return key && s.labels?.[key] ? `${s.labels[key]} ${v}` : v
  })
  return parts.join(' · ') + (m.live.length > 3 ? ` · +${m.live.length - 3}` : '')
}
</script>

<template>
  <div class="flex flex-wrap items-center gap-2">
    <p class="text-sm text-muted-foreground">
      Rules turn metrics into alerts. Each condition compares a metric the agent collects with a threshold.
    </p>
    <div class="ml-auto flex gap-2">
      <Button variant="outline" :aria-expanded="showRef" aria-controls="metric-ref" @click="showRef = !showRef">
        <BookOpen /> Metrics reference
      </Button>
      <Button v-if="admin" @click="openRule()">New rule</Button>
    </div>
  </div>

  <Card v-if="showRef" id="metric-ref">
    <CardHeader class="flex flex-row flex-wrap items-center justify-between gap-2">
      <div>
        <CardTitle>Metrics reference</CardTitle>
        <CardDescription>What each metric measures, where it comes from and its current value on this server.</CardDescription>
      </div>
      <Input v-model="q" class="max-w-xs" placeholder="Search (disk, redis, cpu.total_pct…)" aria-label="Search metrics" />
    </CardHeader>
    <CardContent class="max-h-[32rem] space-y-4 overflow-y-auto">
      <p v-if="!refGroups.length" class="text-sm text-muted-foreground">No metric matches “{{ q }}”.</p>
      <section v-for="g in refGroups" :key="g.name" :aria-label="g.name">
        <h3 class="mb-1 text-sm font-medium">{{ g.name }}</h3>
        <Table>
          <TableBody>
            <TableRow v-for="m in g.items" :key="m.name">
              <TableCell class="w-64 align-top">
                <div class="font-medium">{{ m.title }}</div>
                <div class="font-mono text-xs text-muted-foreground">
                  {{ m.name }}<template v-if="m.labels?.length">{{ '{' + m.labels.join(', ') + '}' }}</template>
                </div>
              </TableCell>
              <TableCell class="text-xs whitespace-normal text-muted-foreground">{{ m.description }}</TableCell>
              <TableCell class="w-48 text-right align-top text-xs tabular-nums">{{ liveSummary(m) }}</TableCell>
            </TableRow>
          </TableBody>
        </Table>
      </section>
    </CardContent>
  </Card>

  <Card>
    <CardContent>
      <LoadState
        :pending="pending"
        :error="error"
        :empty="!data?.length"
        empty-text="No alert rules. Without rules, no alerts fire."
      >
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Rule</TableHead>
              <TableHead>Alerts when</TableHead>
              <TableHead>For</TableHead>
              <TableHead>Severity</TableHead>
              <TableHead>Channels</TableHead>
              <TableHead>Enabled</TableHead>
              <TableHead><span class="sr-only">Actions</span></TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            <TableRow v-for="r in data" :key="r.id">
              <TableCell class="align-top">
                <div class="font-medium">{{ r.name || r.id }}</div>
                <div class="font-mono text-xs text-muted-foreground">
                  {{ r.id }}
                  <span v-if="r.builtin">· built-in</span>
                </div>
              </TableCell>
              <TableCell class="max-w-md align-top whitespace-normal">
                <div v-if="r.expr" class="flex items-start gap-1">
                  <span>{{ r.summary || r.expr }}</span>
                  <Tooltip v-if="ruleMetrics(r).length">
                    <TooltipTrigger as-child>
                      <button type="button" class="mt-0.5 shrink-0 text-muted-foreground" :aria-label="`About the metrics of ${r.id}`">
                        <Info class="size-3.5" />
                      </button>
                    </TooltipTrigger>
                    <TooltipContent class="max-w-sm space-y-2">
                      <p v-for="m in ruleMetrics(r)" :key="m.name">
                        <span class="font-medium">{{ m.title }}</span>
                        <span class="font-mono"> ({{ m.name }})</span>: {{ m.description }}
                      </p>
                    </TooltipContent>
                  </Tooltip>
                </div>
                <span v-else class="text-muted-foreground">Raised by the agent itself (no metric condition)</span>
                <code v-if="r.expr" class="mt-0.5 block text-xs break-all text-muted-foreground">{{ r.expr }}</code>
              </TableCell>
              <TableCell class="align-top whitespace-nowrap">{{ r.expr ? (Number(r.for) ? forLabel(Number(r.for)) : 'immediately') : '-' }}</TableCell>
              <TableCell class="align-top"><StateBadge :value="r.severity" /></TableCell>
              <TableCell class="align-top">{{ (r.channels || []).join(', ') || '-' }}</TableCell>
              <TableCell class="align-top">
                <Switch
                  :model-value="r.enabled"
                  :disabled="!admin"
                  :aria-label="`Enable ${r.id}`"
                  @update:model-value="toggle(r)"
                />
              </TableCell>
              <TableCell class="text-right align-top whitespace-nowrap">
                <template v-if="admin">
                  <Button variant="ghost" size="sm" @click="openRule(r)">Edit</Button>
                  <ConfirmButton
                    v-if="!r.builtin"
                    :title="`Delete rule ${r.id}?`"
                    confirm="Delete"
                    description="Open alerts from this rule stop being re-sent."
                    :action="() => del(r)"
                  >
                    Delete
                  </ConfirmButton>
                </template>
              </TableCell>
            </TableRow>
          </TableBody>
        </Table>
      </LoadState>
    </CardContent>
  </Card>

  <AlertsRuleBuilder v-model:open="open" :rule="editing" :metrics="metrics || []" :channels="channels || []" @saved="refresh" />
</template>
