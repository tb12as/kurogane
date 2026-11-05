<script setup lang="ts">
import { toast } from 'vue-sonner'
import { Plus, Trash2 } from '@lucide/vue'
import type { AlertRule, Channel, MetricDef, Op, RuleCondition } from '~/types/models'

// Guided rule editor: metric, filter, comparison, value and duration are choices; the expression is built from
// them (composables/rules.ts) and saved through the existing rule API.
const props = defineProps<{ rule: AlertRule | null; metrics: MetricDef[]; channels: Channel[] }>()
const open = defineModel<boolean>('open', { required: true })
const emit = defineEmits<{ saved: [] }>()

type Row = { metric: string; labels: Record<string, string>; op: Op; value: number; custom: boolean }
const ANY = '__any'
const CUSTOM = '__custom'
const byName = computed(() => Object.fromEntries(props.metrics.map(m => [m.name, m])))

const f = reactive({
  id: '',
  idTouched: false,
  name: '',
  join: 'and' as 'and' | 'or',
  rows: [] as Row[],
  forNs: 300e9,
  severity: 'warning',
  channels: [] as string[],
  tags: '',
  enabled: true,
})
const editing = computed(() => !!props.rule)
// a rule the builder cannot represent (mixed and/or, unknown metric or label) keeps its expression as is
const complex = ref(false)

// up-style states alert on 0 ("down"), flag-style states alert on 1 ("required", "stale")
function alertValue(d: MetricDef): number {
  return ['up', 'running', 'passes', 'ok'].includes(d.states?.['1'] ?? 'up') ? 0 : 1
}
function defaultRow(name: string): Row {
  const d = byName.value[name]
  if (!d) return { metric: name, labels: {}, op: '>', value: 0, custom: false }
  if (d.unit === 'bool') return { metric: name, labels: {}, op: '==', value: alertValue(d), custom: false }
  const p = d.presets
  const value = d.default_op === '<' ? (p[1] ?? p[0] ?? 0) : (p[Math.floor(p.length * 0.6)] ?? 0)
  return { metric: name, labels: {}, op: d.default_op, value, custom: false }
}
function fromCondition(c: RuleCondition): Row | null {
  const d = byName.value[c.metric]
  if (!d) return null
  for (const k of Object.keys(c.labels || {})) if (!d.labels?.includes(k)) return null
  let { op, value } = c
  if (d.unit === 'bool') {
    const s = boolState(d, op, value)
    if (!s) return null
    op = '=='
    value = s === (d.states?.['1'] ?? 'up') ? 1 : 0
  }
  return { metric: c.metric, labels: { ...(c.labels || {}) }, op, value, custom: !d.presets.includes(value) }
}

watch(open, o => {
  if (!o) return
  const r = props.rule
  complex.value = false
  Object.assign(f, { id: '', idTouched: false, name: '', join: 'and', rows: [], forNs: 300e9, severity: 'warning',
    channels: [], tags: '', enabled: true })
  if (!r) {
    f.rows = [defaultRow('cpu.total_pct')]
    return
  }
  f.id = r.id
  f.idTouched = true
  f.name = r.name
  f.forNs = typeof r.for === 'number' ? r.for : (parseDur(r.for) ?? 0) * 1e6
  f.severity = r.severity
  f.channels = [...(r.channels || [])]
  f.tags = (r.tags || []).join(', ')
  f.enabled = r.enabled
  const rows = (r.conditions?.items || []).map(fromCondition)
  if (!r.conditions || rows.some(x => !x)) {
    complex.value = true
    return
  }
  f.join = r.conditions.join
  f.rows = rows as Row[]
})

watch(
  () => f.name,
  n => {
    if (!editing.value && !f.idTouched) f.id = slug(n)
  },
)

function setMetric(row: Row, name: string) {
  Object.assign(row, defaultRow(name))
}
function liveFor(row: Row) {
  const d = byName.value[row.metric]
  return (d?.live || []).filter(s => Object.entries(row.labels).every(([k, v]) => !v || s.labels?.[k] === v))
}
function labelOptions(row: Row, key: string) {
  const d = byName.value[row.metric]
  const seen = new Set<string>()
  for (const s of d?.live || []) if (s.labels?.[key]) seen.add(s.labels[key])
  if (row.labels[key]) seen.add(row.labels[key])
  return [
    { value: ANY, label: `Any ${key} (alert per ${key})` },
    ...[...seen].sort().map(v => ({ value: v, label: `${key} ${v}` })),
  ]
}
function setLabel(row: Row, key: string, v: string) {
  const labels = { ...row.labels }
  if (v === ANY) delete labels[key]
  else labels[key] = v
  row.labels = labels
}
function valueOptions(row: Row) {
  const d = byName.value[row.metric]
  if (!d) return []
  const vals = [...d.presets]
  if (!row.custom && !vals.includes(row.value)) vals.push(row.value)
  return [
    ...vals.sort((a, b) => a - b).map(v => ({ value: numText(v), label: formatValue(d, v) })),
    { value: CUSTOM, label: 'Custom…' },
  ]
}
function setValue(row: Row, v: string) {
  if (v === CUSTOM) {
    row.custom = true
    return
  }
  row.custom = false
  row.value = Number(v)
}
function boolOptions(row: Row) {
  const d = byName.value[row.metric]
  return [
    { value: '1', label: `is ${d?.states?.['1'] ?? 'up'}` },
    { value: '0', label: `is ${d?.states?.['0'] ?? 'down'}` },
  ]
}

const forOptions = computed(() => {
  const o = FOR_OPTIONS.map(x => ({ value: String(x.ns), label: x.label }))
  if (!FOR_OPTIONS.some(x => x.ns === f.forNs)) o.push({ value: String(f.forNs), label: forLabel(f.forNs) })
  return o.sort((a, b) => Number(a.value) - Number(b.value))
})
const forModel = computed({ get: () => String(f.forNs), set: v => (f.forNs = Number(v)) })

const conditions = computed<RuleCondition[]>(() => f.rows.map(r => ({ metric: r.metric, labels: r.labels, op: r.op, value: r.value })))
const expr = computed(() => (complex.value ? (props.rule?.expr ?? '') : buildExpr(f.join, conditions.value)))
const sentence = computed(() => {
  if (complex.value) return props.rule?.summary || props.rule?.expr || ''
  return conditions.value.map(c => describe(c, byName.value[c.metric])).join(` ${f.join} `)
})
const perLabel = computed(() => {
  const keys = new Set<string>()
  for (const r of f.rows) for (const k of byName.value[r.metric]?.labels || []) if (!r.labels[k]) keys.add(k)
  return [...keys]
})
// "would it fire right now?" from the agent's current values (each condition true for any matching series)
const now = computed(() => {
  if (complex.value || !f.rows.length) return null
  const per = f.rows.map(r => {
    const live = liveFor(r)
    return live.length ? live.some(s => matches(r, s)) : null
  })
  if (per.some(x => x === null)) return null
  return f.join === 'and' ? per.every(Boolean) : per.some(Boolean)
})

function invalid(): string {
  if (!/^[a-z0-9_]+$/.test(f.id)) return 'The ID may only contain lower-case letters, digits and _.'
  if (!complex.value && !f.rows.length) return 'Add at least one condition.'
  for (const r of f.rows) {
    const d = byName.value[r.metric]
    if (!d) return 'Choose a metric for every condition.'
    if (!Number.isFinite(r.value)) return `Enter a number for ${d.title}.`
    if (d.min !== undefined && r.value < d.min) return `${d.title}: the value must be at least ${formatValue(d, d.min)}.`
    if (d.max !== undefined && r.value > d.max) return `${d.title}: the value must be at most ${formatValue(d, d.max)}.`
  }
  return ''
}
const saving = ref(false)
async function save() {
  const err = invalid()
  if (err) return void toast.error(err)
  const body: Record<string, unknown> = {
    name: f.name,
    for: `${Math.round(f.forNs / 1e9)}s`,
    severity: f.severity,
    channels: f.channels,
    tags: f.tags.split(',').map(s => s.trim()).filter(Boolean),
    enabled: f.enabled,
  }
  if (!complex.value) body.expr = expr.value
  saving.value = true
  const ok = editing.value
    ? await run(() => api.put(`/alerts/rules/${encodeURIComponent(f.id)}`, body), 'Rule saved')
    : await run(() => api.post('/alerts/rules', { ...body, id: f.id }), 'Rule created')
  saving.value = false
  if (ok === undefined) return
  open.value = false
  emit('saved')
}
function toggleCh(n: string, on: boolean | 'indeterminate') {
  f.channels = on === true ? [...f.channels, n] : f.channels.filter(c => c !== n)
}
function liveText(row: Row) {
  const d = byName.value[row.metric]
  const live = liveFor(row)
  if (!d || !live.length) return ''
  const key = d.labels?.[0]
  const parts = live.slice(0, 4).map(s => {
    const v = d.unit === 'bool' ? (d.states?.[String(s.value)] ?? numText(s.value)) : formatValue(d, Math.round(s.value * 10) / 10)
    return key && s.labels?.[key] ? `${s.labels[key]} ${v}` : v
  })
  return `Now: ${parts.join(' · ')}${live.length > 4 ? ` · +${live.length - 4} more` : ''}`
}
</script>

<template>
  <Dialog v-model:open="open">
    <DialogScrollContent class="sm:max-w-3xl">
      <DialogHeader>
        <DialogTitle>{{ editing ? `Edit rule ${rule?.name || rule?.id}` : 'New alert rule' }}</DialogTitle>
        <DialogDescription>Pick what to watch and when it should alert. Kurogane checks it on every collection.</DialogDescription>
      </DialogHeader>
      <form class="space-y-5" @submit.prevent="save">
        <div class="grid gap-3 sm:grid-cols-2">
          <div class="space-y-1">
            <Label for="r-name">Name</Label>
            <Input id="r-name" v-model="f.name" placeholder="Root disk almost full" required />
          </div>
          <div class="space-y-1">
            <Label for="r-id">ID</Label>
            <Input
              id="r-id"
              v-model="f.id"
              class="font-mono"
              :disabled="editing"
              required
              pattern="[a-z0-9_]+"
              placeholder="root_disk_full"
              @input="f.idTouched = true"
            />
          </div>
        </div>

        <section aria-labelledby="r-cond" class="space-y-3">
          <div class="flex flex-wrap items-center justify-between gap-2">
            <h3 id="r-cond" class="text-sm font-medium">Condition</h3>
            <div v-if="!complex && f.rows.length > 1" class="flex items-center gap-2 text-sm">
              <span class="text-muted-foreground">Alert when</span>
              <FormSelect
                v-model="f.join"
                label="Combine conditions"
                class="w-52"
                :options="[
                  { value: 'and', label: 'all conditions match' },
                  { value: 'or', label: 'any condition matches' },
                ]"
              />
            </div>
          </div>

          <Alert v-if="complex">
            <AlertTitle>Defined in the configuration</AlertTitle>
            <AlertDescription>
              <p class="font-medium">{{ rule?.summary }}</p>
              <code class="mt-1 block text-xs break-all">{{ rule?.expr }}</code>
              <p class="mt-1">
                This condition mixes "and" and "or" (or uses a metric the builder does not know), so it is kept as is.
                Change it in config.yaml; duration, severity, channels and on/off can be changed here.
              </p>
            </AlertDescription>
          </Alert>

          <div v-for="(row, i) in f.rows" v-else :key="i" class="space-y-2 rounded-lg border p-3">
            <div class="grid gap-2 md:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)_minmax(0,1fr)_auto] md:items-start">
              <AlertsMetricPicker
                :id="`r-metric-${i}`"
                :model-value="row.metric"
                :metrics="metrics"
                @update:model-value="v => setMetric(row, v)"
              />
              <template v-if="byName[row.metric]?.unit === 'bool'">
                <FormSelect
                  :model-value="numText(row.value)"
                  :options="boolOptions(row)"
                  label="State"
                  class="md:col-span-2"
                  @update:model-value="v => (row.value = Number(v))"
                />
              </template>
              <template v-else>
                <FormSelect v-model="row.op" :options="OPS" label="Comparison" />
                <div class="space-y-1">
                  <FormSelect
                    :model-value="row.custom ? '__custom' : numText(row.value)"
                    :options="valueOptions(row)"
                    label="Threshold"
                    @update:model-value="v => setValue(row, v ?? '')"
                  />
                  <div v-if="row.custom" class="flex items-center gap-2">
                    <Input
                      v-model.number="row.value"
                      type="number"
                      step="any"
                      :min="byName[row.metric]?.min"
                      :max="byName[row.metric]?.max"
                      class="tabular-nums"
                      aria-label="Custom threshold"
                    />
                    <span class="shrink-0 text-xs text-muted-foreground">{{ UNIT_SUFFIX[byName[row.metric]?.unit ?? ''] }}</span>
                  </div>
                </div>
              </template>
              <Button
                v-if="f.rows.length > 1"
                type="button"
                variant="ghost"
                size="icon"
                :aria-label="`Remove condition ${i + 1}`"
                @click="f.rows.splice(i, 1)"
              >
                <Trash2 />
              </Button>
            </div>

            <div v-if="byName[row.metric]?.labels?.length" class="flex flex-wrap gap-2">
              <div v-for="key in byName[row.metric]!.labels" :key="key" class="w-full sm:w-64">
                <FormSelect
                  :model-value="row.labels[key] || ANY"
                  :options="labelOptions(row, key)"
                  :label="`Filter by ${key}`"
                  @update:model-value="v => setLabel(row, key, v ?? ANY)"
                />
              </div>
            </div>

            <p v-if="byName[row.metric]" class="text-xs text-muted-foreground">
              <span class="font-mono">{{ row.metric }}</span> · {{ byName[row.metric]!.description }}
              <span v-if="liveText(row)" class="mt-0.5 block font-medium text-foreground">{{ liveText(row) }}</span>
            </p>
          </div>

          <Button
            v-if="!complex"
            type="button"
            variant="outline"
            size="sm"
            @click="f.rows.push(defaultRow('mem.available_pct'))"
          >
            <Plus /> Add condition
          </Button>
        </section>

        <div class="grid gap-3 sm:grid-cols-2">
          <div class="space-y-1">
            <Label for="r-for">Only alert after the condition holds for</Label>
            <FormSelect id="r-for" v-model="forModel" :options="forOptions" label="Duration" />
          </div>
          <div class="space-y-1">
            <Label for="r-sev">Severity</Label>
            <FormSelect
              id="r-sev"
              v-model="f.severity"
              :options="[
                { value: 'info', label: 'Info' },
                { value: 'warning', label: 'Warning' },
                { value: 'critical', label: 'Critical' },
              ]"
            />
          </div>
        </div>

        <div class="rounded-lg bg-muted/60 p-3 text-sm" aria-live="polite">
          <p>
            <span class="text-muted-foreground">Fires when </span>
            <span class="font-medium">{{ sentence || '…' }}</span>
            <span class="text-muted-foreground">
              {{ f.forNs ? ` for ${forLabel(f.forNs).replace(/^1 /, 'one ')}` : ', immediately' }}<template
                v-if="perLabel.length"
                >, separately for each {{ perLabel.join(' and ') }}</template
              >.
            </span>
          </p>
          <p v-if="now !== null" class="mt-1 text-xs">
            Right now:
            <span :class="now ? 'font-medium text-warn' : 'text-muted-foreground'">
              {{ now ? 'the condition is met' : 'the condition is not met' }}
            </span>
          </p>
          <code class="mt-1 block text-xs break-all text-muted-foreground">{{ expr }}</code>
        </div>

        <fieldset class="space-y-1">
          <legend class="text-sm font-medium">Send to</legend>
          <p v-if="!channels.length" class="text-xs text-muted-foreground">
            No channels yet. Add one under Channels; until then the alert only shows in Events.
          </p>
          <div class="flex flex-wrap gap-3">
            <label v-for="c in channels" :key="c.name" class="flex items-center gap-2 text-sm">
              <Checkbox :model-value="f.channels.includes(c.name)" @update:model-value="v => toggleCh(c.name, v)" />
              {{ c.name }}
            </label>
          </div>
        </fieldset>
        <div class="grid gap-3 sm:grid-cols-2">
          <div class="space-y-1">
            <Label for="r-tags">Tags (comma separated)</Label>
            <Input id="r-tags" v-model="f.tags" placeholder="prod, web" />
          </div>
          <label class="flex items-center gap-2 self-end pb-2 text-sm">
            <Switch v-model="f.enabled" />
            Enabled
          </label>
        </div>
        <DialogFooter>
          <Button type="button" variant="outline" @click="open = false">Cancel</Button>
          <Button type="submit" :disabled="saving">{{ editing ? 'Save rule' : 'Create rule' }}</Button>
        </DialogFooter>
      </form>
    </DialogScrollContent>
  </Dialog>
</template>
