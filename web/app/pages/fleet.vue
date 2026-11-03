<script setup lang="ts">
import { toast } from 'vue-sonner'
import type { FleetOp, Person } from '~/types/models'

useHead({ title: 'Fleet · ServerKeeper' })
if (!useFleet().value) await navigateTo('/', { replace: true })
const tab = useTab('people')
const admin = computed(() => can('admin'))

const {
  data: people,
  pending: pPending,
  error: pErr,
  refresh: refreshPeople,
} = useAsyncData('fleet.people', async () => list<Person>(await api.get('/fleet/people'), 'people'))
const { data: groupMap } = useAsyncData('fleet.groups', async () => (await api.get('/fleet/groups')) || {})
const groups = computed(() =>
  Object.entries((groupMap.value || {}) as Record<string, string[]>).map(([name, members]) => ({ name, members })),
)
const { data: servers } = useAsyncData('fleet.servers', async () => list(await api.get('/servers')))
const {
  data: ops,
  pending: oPending,
  error: oErr,
  refresh: refreshOps,
} = useAsyncData('fleet.ops', async () => list<FleetOp>(await api.get('/fleet/ops'), 'ops'))

// person: created first, then the optional key is attached
const pOpen = ref(false)
const p = reactive({ name: '', email: '', groups: '', key: '', login: 'deploy' })
async function addPerson() {
  const groups = p.groups.split(',').map(s => s.trim()).filter(Boolean)
  const made = await run(() => api.post('/fleet/people', { name: p.name, email: p.email, groups }))
  if (!made) return
  if (p.key.trim()) {
    const body = { public_key: p.key.trim(), login_user: p.login }
    await run(() => api.post('/fleet/people/{id}/keys', body, { path: { id: made.id! } }))
  }
  toast.success('Person added')
  pOpen.value = false
  Object.assign(p, { name: '', email: '', groups: '', key: '' })
  refreshPeople()
  refreshNuxtData('fleet.groups')
}

// push / revoke: the backend queues ops right away (no dry run), so the preview is built here
const push = reactive({ by: 'group', target: '', user: 'deploy' })
const pushOpen = ref(false)
const targets = computed(() =>
  push.by === 'group'
    ? groups.value.map(g => ({ value: g.name, label: `${g.name} (${g.members.length})` }))
    : (people.value || []).map(x => ({ value: x.id, label: x.name })),
)
const pushPeople = computed(() =>
  (people.value || []).filter(x => (push.by === 'group' ? x.groups?.includes(push.target) : x.id === push.target)),
)
watch(
  () => push.by,
  () => (push.target = ''),
)
async function pushPreview() {
  const keys = pushPeople.value.flatMap(x => (x.keys || []).map(k => ({ ...k, who: x.name })))
  const n = servers.value?.length || 0
  const warnings = keys.length ? [] : ['Nobody in this selection has a key yet; nothing would be pushed.']
  return {
    diff: keys.map(k => `+ ${k.public_key}  # ${k.who} -> ${push.user || k.login_user}`).join('\n'),
    impact: [
      `${keys.length} key(s) from ${pushPeople.value.length} person(s) are added on ${n} server(s): ` +
        `${keys.length * n} add_key operation(s).`,
      'Offline servers apply them when they reconnect; check Operations for progress.',
    ],
    warnings,
  }
}
const revFp = ref('')
const revOpen = ref(false)
async function revokePreview() {
  const holders = (people.value || []).filter(x => x.keys?.some(k => k.fingerprint === revFp.value))
  return {
    diff: `- ${revFp.value}`,
    impact: [
      `Removed from every user on all ${servers.value?.length || 0} enrolled server(s).`,
      holders.length
        ? `Also removed from: ${holders.map(x => x.name).join(', ')}.`
        : 'No person in the inventory owns this key.',
      'Offline servers apply the revoke when they reconnect; check Operations for progress.',
    ],
  }
}
function opsDone(msg: string) {
  toast.success(msg)
  refreshOps()
  tab.value = 'ops'
}

// enrollment token (one-time, expires in 1 h, shown once)
const enrollName = ref('')
const enroll = ref<{ token?: string, name?: string, expires_at?: string } | null>(null)
const enrollYaml = computed(() =>
  enroll.value ? `central:\n  addr: ${location.hostname}:9444\n  enrollment_token: ${enroll.value.token}` : '',
)
async function createEnroll() {
  const r = await run(() => api.post('/fleet/enrollment-tokens', { name: enrollName.value }))
  if (r) enroll.value = r
}
</script>

<template>
  <h1 class="text-2xl font-semibold">Fleet</h1>
  <Tabs v-model="tab">
    <TabsList class="h-auto flex-wrap justify-start">
      <TabsTrigger value="people">People and groups</TabsTrigger>
      <TabsTrigger value="keys">Push / revoke keys</TabsTrigger>
      <TabsTrigger value="ops">Operations</TabsTrigger>
      <TabsTrigger value="enroll">Enroll server</TabsTrigger>
    </TabsList>

    <TabsContent value="people" class="space-y-3">
      <div class="flex"><Button v-if="admin" class="ml-auto" @click="pOpen = true">Add person</Button></div>
      <LoadState :pending="pPending" :error="pErr" :empty="!people?.length" empty-text="No people yet.">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Name</TableHead>
              <TableHead>Email</TableHead>
              <TableHead>Groups</TableHead>
              <TableHead>Keys</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            <TableRow v-for="x in people" :key="x.id">
              <TableCell class="font-medium">{{ x.name }}</TableCell>
              <TableCell>{{ x.email }}</TableCell>
              <TableCell>
                <Badge v-for="g in x.groups" :key="g" variant="secondary" class="mr-1">{{ g }}</Badge>
              </TableCell>
              <TableCell class="font-mono text-xs">
                <div v-for="k in x.keys" :key="k.fingerprint" class="truncate" :title="k.fingerprint">
                  {{ k.login_user }}: {{ k.fingerprint }}
                </div>
              </TableCell>
            </TableRow>
          </TableBody>
        </Table>
      </LoadState>
      <Card v-if="groups?.length">
        <CardHeader><CardTitle class="text-sm">Groups</CardTitle></CardHeader>
        <CardContent>
          <ul class="divide-y text-sm">
            <li v-for="g in groups" :key="g.name" class="flex flex-wrap gap-2 py-1.5">
              <span class="font-medium">{{ g.name }}</span>
              <span class="text-muted-foreground">{{ g.members.join(', ') }}</span>
            </li>
          </ul>
        </CardContent>
      </Card>
    </TabsContent>

    <TabsContent value="keys" class="grid gap-4 lg:grid-cols-2">
      <Card>
        <CardHeader>
          <CardTitle>Push keys</CardTitle>
          <CardDescription>Adds every key of a person or group to a login user on all servers.</CardDescription>
        </CardHeader>
        <CardContent>
          <form class="space-y-3" @submit.prevent="pushOpen = true">
            <div class="grid grid-cols-2 gap-2">
              <div class="space-y-1">
                <Label for="pu-by">Target</Label>
                <FormSelect id="pu-by" v-model="push.by" :options="['group', 'person']" />
              </div>
              <div class="space-y-1">
                <Label for="pu-t">{{ push.by === 'group' ? 'Group' : 'Person' }}</Label>
                <FormSelect id="pu-t" v-model="push.target" :options="targets" placeholder="Choose…" />
              </div>
            </div>
            <div class="space-y-1">
              <Label for="pu-u">Login user</Label>
              <Input id="pu-u" v-model="push.user" required />
            </div>
            <Button type="submit" :disabled="!admin || !push.target">Preview push</Button>
          </form>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Revoke key everywhere</CardTitle>
          <CardDescription>Removes a key from every user on every server, e.g. when someone leaves.</CardDescription>
        </CardHeader>
        <CardContent>
          <form class="space-y-3" @submit.prevent="revOpen = true">
            <div class="space-y-1">
              <Label for="rv-fp">Fingerprint</Label>
              <Input id="rv-fp" v-model="revFp" required class="font-mono" placeholder="SHA256:…" />
            </div>
            <Button type="submit" variant="destructive" :disabled="!admin">Preview revoke</Button>
          </form>
        </CardContent>
      </Card>
    </TabsContent>

    <TabsContent value="ops">
      <LoadState :pending="oPending" :error="oErr" :empty="!ops?.length" empty-text="No fleet operations yet.">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Created</TableHead>
              <TableHead>Kind</TableHead>
              <TableHead>Server</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Result</TableHead>
              <TableHead>By</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            <TableRow v-for="o in ops" :key="o.id">
              <TableCell class="whitespace-nowrap">{{ fmtDate(o.created_at) }}</TableCell>
              <TableCell class="font-mono text-xs">{{ o.kind }}</TableCell>
              <TableCell>{{ o.server_id }}</TableCell>
              <TableCell><StateBadge :value="o.status" /></TableCell>
              <TableCell class="max-w-md whitespace-normal text-xs">{{ o.result }}</TableCell>
              <TableCell>{{ o.created_by }}</TableCell>
            </TableRow>
          </TableBody>
        </Table>
      </LoadState>
    </TabsContent>

    <TabsContent value="enroll">
      <Card>
        <CardHeader>
          <CardTitle>Enrollment token</CardTitle>
          <CardDescription>One-time token, valid for 1 hour. Add the snippet to the new agent's config.yaml.</CardDescription>
        </CardHeader>
        <CardContent class="space-y-3">
          <form class="flex flex-wrap items-end gap-2" @submit.prevent="createEnroll">
            <div class="space-y-1">
              <Label for="en-name">Server name</Label>
              <Input id="en-name" v-model="enrollName" required placeholder="web-02" />
            </div>
            <Button type="submit" :disabled="!admin">Create token</Button>
          </form>
          <div v-if="enroll" class="space-y-2 rounded-md border p-3 text-sm">
            <p>For {{ enroll.name }}, expires {{ ago(enroll.expires_at) }}. Shown once.</p>
            <pre class="overflow-auto rounded bg-muted p-2 font-mono text-xs">{{ enrollYaml }}</pre>
          </div>
        </CardContent>
      </Card>
    </TabsContent>
  </Tabs>

  <Dialog v-model:open="pOpen">
    <DialogContent>
      <DialogHeader>
        <DialogTitle>Add person</DialogTitle>
        <DialogDescription>People own keys; groups decide where they are pushed.</DialogDescription>
      </DialogHeader>
      <form class="space-y-3" @submit.prevent="addPerson">
        <div class="grid gap-3 sm:grid-cols-2">
          <div class="space-y-1">
            <Label for="pe-n">Name</Label>
            <Input id="pe-n" v-model="p.name" required />
          </div>
          <div class="space-y-1">
            <Label for="pe-e">Email</Label>
            <Input id="pe-e" v-model="p.email" type="email" />
          </div>
        </div>
        <div class="space-y-1">
          <Label for="pe-g">Groups (comma separated)</Label>
          <Input id="pe-g" v-model="p.groups" placeholder="devs, ops" />
        </div>
        <div class="space-y-1">
          <Label for="pe-k">Public key (optional)</Label>
          <Textarea id="pe-k" v-model="p.key" rows="3" class="font-mono text-xs" />
        </div>
        <div class="space-y-1">
          <Label for="pe-l">Login user for this key</Label>
          <Input id="pe-l" v-model="p.login" />
        </div>
        <DialogFooter><Button type="submit">Add person</Button></DialogFooter>
      </form>
    </DialogContent>
  </Dialog>

  <RiskDialog
    v-model:open="pushOpen"
    :title="`Push keys of ${targets.find(t => t.value === push.target)?.label || push.target} to ${push.user}`"
    confirm="Push to all servers"
    :preview="pushPreview"
    :apply="() => api.post('/fleet/keys/push', { [push.by]: push.target, user: push.user })"
    @done="() => opsDone('Push queued')"
  />
  <RiskDialog
    v-model:open="revOpen"
    title="Revoke key on every server"
    confirm="Revoke everywhere"
:preview="revokePreview"
    :apply="() => api.post('/fleet/keys/revoke', { fingerprint: revFp })"
    @done="() => opsDone('Revoke queued')"
  >
    <p class="break-all font-mono text-xs">{{ revFp }}</p>
  </RiskDialog>
</template>
