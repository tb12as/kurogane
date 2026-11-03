<script setup lang="ts">
import { toast } from 'vue-sonner'

interface Row {
  key: string
  current: string
  recommended: string
  ok: boolean
  note: string
}

const live = useLive()
const { data, pending, error, refresh } = useAsyncData('ssh.config', async () => {
  const r: any = await api.get('/ssh/config')
  const arr = list<any>(r, 'settings')
  let rows: Row[]
  if (arr.length) {
    rows = arr.map(x => ({
      key: x.key ?? x.setting ?? x.name,
      current: String(x.current ?? x.value ?? ''),
      recommended: String(x.recommended ?? ''),
      ok: x.ok ?? x.compliant ?? String(x.current) === String(x.recommended),
      note: x.note ?? x.notes ?? '',
    }))
  } else {
    const cur = r?.current || {},
      rec = r?.recommended || {}
    rows = Object.keys({ ...cur, ...rec })
      .sort()
      .map(k => ({
        key: k,
        current: String(cur[k] ?? ''),
        recommended: String(rec[k] ?? ''),
        ok: !(k in rec) || cur[k] === rec[k],
        note: '',
      }))
  }
  return { rows, dropin: r?.dropin ?? r?.path ?? '' }
})
watch(
  () => live.tick.value.ssh,
  () => refresh(),
)

// change form -> dry-run review -> apply with rollback timer
const formOpen = ref(false)
const reviewOpen = ref(false)
const edits = ref<{ key: string; value: string }[]>([])
const rollback = ref(120)

// "no or prohibit-password" -> "no"; prose like "custom (e.g. 2222)" or "explicit list" is not a value
const concrete = (r: Row) => /^[\w.,@:+-]+$/.test(r.recommended.split(/\s+or\s+/)[0] || '')
const fixable = computed(() => (data.value?.rows || []).filter(r => !r.ok && concrete(r)))
function openChange(rows: Row[]) {
  edits.value = rows.map(r => ({ key: r.key, value: concrete(r) ? r.recommended.split(/\s+or\s+/)[0]! : r.current }))
  if (!edits.value.length) edits.value = [{ key: '', value: '' }]
  formOpen.value = true
}
const body = (dry: boolean) => ({
  set: Object.fromEntries(edits.value.filter(e => e.key.trim()).map(e => [e.key.trim(), e.value.trim()])),
  rollback: `${rollback.value}s`,
  dry_run: dry,
})
function review() {
  formOpen.value = false
  reviewOpen.value = true
}
function applied() {
  toast.success(`Applied. Confirm within ${rollback.value}s or it rolls back automatically.`)
  live.tick.value.ssh++
  refresh()
}
const impact = computed(() => [
  `sshd_config is validated with sshd -t, backed up, then sshd is reloaded (existing sessions stay connected).`,
  `If you do not confirm within ${rollback.value} seconds, the previous config is restored automatically.`,
  ...edits.value
    .filter(e => /password|root|allow|port|pubkey/i.test(e.key))
    .map(e => `${e.key} = ${e.value} can block logins: test with a new SSH session before confirming.`),
])
</script>

<template>
  <div class="flex flex-wrap items-center gap-2">
    <p class="text-sm text-muted-foreground">Effective sshd settings next to the recommended value.</p>
    <div v-if="can('ssh:write')" class="ml-auto flex gap-2">
      <Button variant="outline" @click="openChange([])">Change setting</Button>
      <Button :disabled="!fixable.length" @click="openChange(fixable)">
        Apply recommended
      </Button>
    </div>
  </div>

  <LoadState :pending="pending" :error="error" :empty="!data?.rows.length">
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Setting</TableHead>
          <TableHead>Current</TableHead>
          <TableHead>Recommended</TableHead>
          <TableHead>Status</TableHead>
          <TableHead>Notes</TableHead>
          <TableHead class="sr-only">Actions</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        <TableRow v-for="r in data!.rows" :key="r.key">
          <TableCell class="font-mono">{{ r.key }}</TableCell>
          <TableCell class="max-w-64 break-all font-mono text-xs">{{ r.current || '(default)' }}</TableCell>
          <TableCell class="max-w-64 break-all font-mono text-xs">{{ r.recommended || '—' }}</TableCell>
          <TableCell><StateBadge :value="r.recommended ? (r.ok ? 'ok' : 'warning') : ''" /></TableCell>
          <TableCell class="text-xs text-muted-foreground">{{ r.note }}</TableCell>
          <TableCell class="text-right">
            <Button v-if="can('ssh:write')" variant="ghost" size="sm" @click="openChange([r])">Change</Button>
          </TableCell>
        </TableRow>
      </TableBody>
    </Table>
  </LoadState>

  <Dialog v-model:open="formOpen">
    <DialogContent class="sm:max-w-xl">
      <DialogHeader>
        <DialogTitle>Change sshd settings</DialogTitle>
        <DialogDescription>Next you will see the dry-run diff before anything is applied.</DialogDescription>
      </DialogHeader>
      <form class="space-y-3" @submit.prevent="review">
        <div v-for="(e, i) in edits" :key="i" class="grid grid-cols-[1fr_1fr_auto] items-end gap-2">
          <div class="space-y-1">
            <Label :for="`k${i}`">Setting</Label>
            <Input :id="`k${i}`" v-model="e.key" class="font-mono" required />
          </div>
          <div class="space-y-1">
            <Label :for="`v${i}`">Value</Label>
            <Input :id="`v${i}`" v-model="e.value" class="font-mono" required />
          </div>
          <Button
            type="button"
            variant="ghost"
            size="sm"
            :aria-label="`Remove ${e.key || 'row'}`"
            :disabled="edits.length === 1"
            @click="edits.splice(i, 1)"
          >
            Remove
          </Button>
        </div>
        <Button type="button" variant="outline" size="sm" @click="edits.push({ key: '', value: '' })">
          Add setting
        </Button>
        <div class="space-y-1">
          <Label for="rb">Rollback timer (seconds)</Label>
          <Input id="rb" v-model.number="rollback" type="number" min="30" max="3600" class="w-32" required />
        </div>
        <DialogFooter><Button type="submit">Preview change</Button></DialogFooter>
      </form>
    </DialogContent>
  </Dialog>

  <RiskDialog
    v-model:open="reviewOpen"
    title="Apply sshd change"
    :confirm="`Apply with ${rollback}s rollback`"
    :impact="impact"
    :preview="() => api.patch('/ssh/config', body(true))"
    :apply="() => api.patch('/ssh/config', body(false))"
    @done="applied"
  >
    <ul class="text-sm">
      <li v-for="e in edits" :key="e.key" class="font-mono">{{ e.key }} → {{ e.value }}</li>
    </ul>
  </RiskDialog>
</template>
