<script setup lang="ts">
import type { AlertRule, Channel } from '~/types/models'

const { data, pending, error, refresh } = useAsyncData('alerts.rules', async () =>
  list<AlertRule>(await api.get('/alerts/rules'), 'rules'),
)
const { data: channels } = useAsyncData('alerts.channels', async () =>
  list<Channel>(await api.get('/alerts/channels'), 'channels'),
)
const admin = computed(() => can('admin'))

const open = ref(false)
const editing = ref<string | null>(null)
const blank = () => ({
  id: '',
  name: '',
  expr: '',
  for: '5m',
  severity: 'warning',
  channels: [] as string[],
  tags: '',
  enabled: true,
})
const f = reactive(blank())
function openRule(r?: AlertRule) {
  editing.value = r?.id ?? null
  const b = blank()
  if (r) {
    Object.assign(b, { id: r.id, name: r.name, expr: r.expr, for: dur(r.for), severity: r.severity, enabled: r.enabled })
    b.channels = [...(r.channels || [])]
    b.tags = (r.tags || []).join(', ')
  }
  Object.assign(f, b)
  open.value = true
}
function toggleCh(n: string, on: boolean | 'indeterminate') {
  f.channels = on === true ? [...f.channels, n] : f.channels.filter(c => c !== n)
}
async function save() {
  if (parseDur(f.for) === null) return toastErr('Duration must look like 30s, 5m or 1h.')
  // the body is decoded strictly: send exactly the ruleReq fields; "for" goes out as a duration string
  const body = {
    ...f,
    tags: f.tags
      .split(',')
      .map(s => s.trim())
      .filter(Boolean),
  }
  const ok = editing.value
    ? await run(() => api.put(`/alerts/rules/${encodeURIComponent(editing.value!)}`, body), 'Rule saved')
    : await run(() => api.post('/alerts/rules', body), 'Rule created')
  if (ok === undefined) return
  open.value = false
  refresh()
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
</script>

<script lang="ts">
import { toast } from 'vue-sonner'
const toastErr = (m: string) => void toast.error(m)
</script>

<template>
  <div class="flex"><Button v-if="admin" class="ml-auto" @click="openRule()">New rule</Button></div>
  <LoadState :pending="pending" :error="error" :empty="!data?.length" empty-text="No alert rules.">
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Rule</TableHead>
          <TableHead>Condition</TableHead>
          <TableHead>For</TableHead>
          <TableHead>Severity</TableHead>
          <TableHead>Channels</TableHead>
          <TableHead>Enabled</TableHead>
          <TableHead class="sr-only">Actions</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        <TableRow v-for="r in data" :key="r.id">
          <TableCell>
            <div class="font-medium">{{ r.name || r.id }}</div>
            <div class="font-mono text-xs text-muted-foreground">
              {{ r.id }}
              <span v-if="r.builtin">· built-in</span>
            </div>
          </TableCell>
          <TableCell class="font-mono text-xs">{{ r.expr }}</TableCell>
          <TableCell>{{ dur(r.for) }}</TableCell>
          <TableCell><StateBadge :value="r.severity" /></TableCell>
          <TableCell>{{ (r.channels || []).join(', ') || '—' }}</TableCell>
          <TableCell>
            <Switch
              :model-value="r.enabled"
              :disabled="!admin"
              :aria-label="`Enable ${r.id}`"
              @update:model-value="toggle(r)"
            />
          </TableCell>
          <TableCell class="whitespace-nowrap text-right">
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

  <Dialog v-model:open="open">
    <DialogScrollContent>
      <DialogHeader>
        <DialogTitle>{{ editing ? 'Edit rule' : 'New rule' }}</DialogTitle>
        <DialogDescription>Fires when the condition holds for the whole duration.</DialogDescription>
      </DialogHeader>
      <form class="space-y-3" @submit.prevent="save">
        <div class="grid gap-3 sm:grid-cols-2">
          <div class="space-y-1">
            <Label for="r-id">ID</Label>
            <Input
              id="r-id"
              v-model="f.id"
              :disabled="!!editing"
              required
              pattern="[a-z0-9_]+"
              placeholder="mem_available_low"
            />
          </div>
          <div class="space-y-1">
            <Label for="r-name">Name</Label>
            <Input id="r-name" v-model="f.name" placeholder="RAM almost full" />
          </div>
        </div>
        <div class="space-y-1">
          <Label for="r-expr">Condition</Label>
          <Input id="r-expr" v-model="f.expr" class="font-mono" required placeholder="mem.available_pct < 10" />
          <p class="text-xs text-muted-foreground">
            Metric names from the catalog, e.g. cpu.total_pct &gt; 90, disk.used_pct{mount="/"} &gt; 85
          </p>
        </div>
        <div class="grid gap-3 sm:grid-cols-2">
          <div class="space-y-1">
            <Label for="r-for">For</Label>
            <Input id="r-for" v-model="f.for" required placeholder="5m" />
          </div>
          <div class="space-y-1">
            <Label for="r-sev">Severity</Label>
            <FormSelect id="r-sev" v-model="f.severity" :options="['info', 'warning', 'critical']" />
          </div>
        </div>
        <fieldset class="space-y-1">
          <legend class="text-sm font-medium">Channels</legend>
          <p v-if="!channels?.length" class="text-xs text-muted-foreground">No channels yet. Add one under Channels.</p>
          <div class="flex flex-wrap gap-3">
            <label v-for="c in channels" :key="c.name" class="flex items-center gap-2 text-sm">
              <Checkbox :model-value="f.channels.includes(c.name)" @update:model-value="v => toggleCh(c.name, v)" />
              {{ c.name }}
            </label>
          </div>
        </fieldset>
        <div class="space-y-1">
          <Label for="r-tags">Tags (comma separated)</Label>
          <Input id="r-tags" v-model="f.tags" />
        </div>
        <label class="flex items-center gap-2 text-sm">
          <Switch v-model="f.enabled" />
          Enabled
        </label>
        <DialogFooter><Button type="submit">Save rule</Button></DialogFooter>
      </form>
    </DialogScrollContent>
  </Dialog>
</template>
