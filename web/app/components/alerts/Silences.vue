<script setup lang="ts">
import type { Silence } from '~/types/models'

const route = useRoute()
const { data, pending, error, refresh } = useAsyncData('alerts.silences', async () =>
  list<Silence>(await api.get('/alerts/silences'), 'silences'),
)

const open = ref(false)
const f = reactive({ server: '', rule: '', tag: '', mode: 'duration', duration: '1h', start: '', end: '', reason: '' })
const local = (d: Date) => new Date(d.getTime() - d.getTimezoneOffset() * 6e4).toISOString().slice(0, 16)

function openNew(q: Record<string, unknown> = {}) {
  const s = (k: string) => (typeof q[k] === 'string' ? (q[k] as string) : '')
  const now = new Date()
  Object.assign(f, {
    server: s('server'),
    rule: s('rule'),
    tag: s('tag'),
    mode: 'duration',
    duration: s('for') || '1h',
    start: local(now),
    end: local(new Date(now.getTime() + 36e5)),
    reason: '',
  })
  open.value = true
}
// deep link from Slack/Discord: /alerts/silence?rule=X&for=1h lands here with the dialog prefilled
onMounted(() => {
  if (route.query.rule || route.query.for || route.query.server || route.query.tag) openNew(route.query)
})
watch(
  () => route.query.rule,
  r => {
    if (r) openNew(route.query)
  },
)

const err = ref('')
async function save() {
  err.value = ''
  if (!f.server && !f.rule && !f.tag)
    return void (err.value = 'Set at least one of server, rule or tag, otherwise every alert is silenced.')
  const body: Record<string, string> = { server: f.server, rule: f.rule, tag: f.tag, reason: f.reason }
  if (f.mode === 'duration') {
    if (!parseDur(f.duration)) return void (err.value = 'Duration must look like 30m, 2h or 1d.')
    body.for = f.duration
  } else {
    const starts = new Date(f.start)
    const ends = new Date(f.end)
    if (!(ends > starts)) return void (err.value = 'End must be after start.')
    body.starts_at = starts.toISOString()
    body.ends_at = ends.toISOString()
  }
  if ((await run(() => api.post('/alerts/silences', body), 'Silence created')) === undefined) return
  open.value = false
  navigateTo({ query: { tab: 'silences' } }, { replace: true })
  refresh()
}
async function del(s: Silence) {
  await run(() => api.del(`/alerts/silences/${s.id}`), 'Silence removed')
  refresh()
}
const activeNow = (s: Silence) =>
  (when(s.starts_at)?.getTime() ?? 0) <= Date.now() && Date.now() < (when(s.ends_at)?.getTime() ?? 0)
</script>

<template>
  <div class="flex"><Button class="ml-auto" @click="openNew()">New silence</Button></div>
  <LoadState :pending="pending" :error="error" :empty="!data?.length" empty-text="No silences.">
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Matches</TableHead>
          <TableHead>Starts</TableHead>
          <TableHead>Ends</TableHead>
          <TableHead>State</TableHead>
          <TableHead>Reason</TableHead>
          <TableHead>By</TableHead>
          <TableHead class="sr-only">Actions</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        <TableRow v-for="s in data" :key="s.id">
          <TableCell class="font-mono text-xs">
            <span v-for="(v, k) in s.matcher" :key="k" class="mr-2">{{ k }}={{ v }}</span>
          </TableCell>
          <TableCell class="whitespace-nowrap">{{ fmtDate(s.starts_at) }}</TableCell>
          <TableCell class="whitespace-nowrap">{{ fmtDate(s.ends_at) }}</TableCell>
          <TableCell>
            <StateBadge
              :value="
                activeNow(s) ? 'active' : (when(s.ends_at)?.getTime() ?? 0) < Date.now() ? 'expired' : 'scheduled'
              "
            />
          </TableCell>
          <TableCell class="whitespace-normal">{{ s.reason }}</TableCell>
          <TableCell>{{ s.created_by }}</TableCell>
          <TableCell class="text-right">
            <ConfirmButton
              :title="'Delete silence?'"
              confirm="Delete"
              description="Matching alerts notify again immediately."
              :action="() => del(s)"
            >
              Delete
            </ConfirmButton>
          </TableCell>
        </TableRow>
      </TableBody>
    </Table>
  </LoadState>

  <Dialog v-model:open="open">
    <DialogScrollContent>
      <DialogHeader>
        <DialogTitle>New silence</DialogTitle>
        <DialogDescription>Matching alerts stay recorded but are not sent to channels.</DialogDescription>
      </DialogHeader>
      <form class="space-y-3" @submit.prevent="save">
        <div class="grid gap-3 sm:grid-cols-3">
          <div class="space-y-1">
            <Label for="s-srv">Server</Label>
            <Input id="s-srv" v-model="f.server" placeholder="web-01" />
          </div>
          <div class="space-y-1">
            <Label for="s-rule">Rule</Label>
            <Input id="s-rule" v-model="f.rule" placeholder="high_cpu" />
          </div>
          <div class="space-y-1">
            <Label for="s-tag">Tag</Label>
            <Input id="s-tag" v-model="f.tag" placeholder="prod" />
          </div>
        </div>
        <Tabs v-model="f.mode">
          <TabsList aria-label="Silence window">
            <TabsTrigger value="duration">Duration</TabsTrigger>
            <TabsTrigger value="window">Start / end</TabsTrigger>
          </TabsList>
          <TabsContent value="duration" class="space-y-1">
            <Label for="s-dur">For</Label>
            <Input id="s-dur" v-model="f.duration" placeholder="2h" class="w-32" />
          </TabsContent>
          <TabsContent value="window" class="grid gap-3 sm:grid-cols-2">
            <div class="space-y-1">
              <Label for="s-start">Start</Label>
              <Input id="s-start" v-model="f.start" type="datetime-local" />
            </div>
            <div class="space-y-1">
              <Label for="s-end">End</Label>
              <Input id="s-end" v-model="f.end" type="datetime-local" />
            </div>
          </TabsContent>
        </Tabs>
        <div class="space-y-1">
          <Label for="s-reason">Reason</Label>
          <Input id="s-reason" v-model="f.reason" placeholder="Maintenance window" />
        </div>
        <p v-if="err" role="alert" class="text-sm text-destructive">{{ err }}</p>
        <DialogFooter><Button type="submit">Create silence</Button></DialogFooter>
      </form>
    </DialogScrollContent>
  </Dialog>
</template>
