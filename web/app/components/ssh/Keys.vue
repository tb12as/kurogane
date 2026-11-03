<script setup lang="ts">
import { toast } from 'vue-sonner'
import type { SSHKey } from '~/types/models'

const { data, pending, error, refresh } = useAsyncData('ssh.keys', async () =>
  list<SSHKey>(await api.get('/ssh/keys'), 'keys'),
)
const live = useLive()
watch(
  () => live.tick.value.ssh,
  () => refresh(),
)
const userFilter = ref('all')
const users = computed(() => [
  { value: 'all', label: 'All users' },
  ...[...new Set((data.value || []).map(k => k.user))].map(u => ({ value: u, label: u })),
])
const rows = computed(() => (data.value || []).filter(k => userFilter.value === 'all' || k.user === userFilter.value))

// weak-key flags come from the backend (PRD §6.1); expiry is checked here
const FLAG: Record<string, string> = {
  'weak-rsa': 'RSA < 3072 bits',
  dsa: 'DSA',
  duplicate: 'duplicate',
  'no-label': 'no owner label',
}
function flags(k: SSHKey): string[] {
  const f = (k.flags || []).map(x => FLAG[x] || x)
  const e = when(k.expires_at)
  if (e && e.getTime() < Date.now()) f.push('expired')
  return f
}

// add dialog
const addOpen = ref(false)
const add = reactive({ user: 'root', source: 'paste', key: '', handle: '', label: '', expires: '' })
async function submitAdd() {
  const body: Record<string, string> = { user: add.user, label: add.label }
  if (add.source === 'paste') body.public_key = add.key.trim()
  else body[add.source] = add.handle.trim()
  if (add.expires) body.expires_at = new Date(add.expires + 'T23:59:59').toISOString()
  const r = await run(() => api.post('/ssh/keys', body), 'Key added')
  if (r === undefined) return
  addOpen.value = false
  Object.assign(add, { key: '', handle: '', label: '', expires: '' })
  refresh()
}

// edit label/expiry
const edit = ref<SSHKey | null>(null)
const editF = reactive({ label: '', expires: '' })
function openEdit(k: SSHKey) {
  edit.value = k
  editF.label = k.label
  editF.expires = when(k.expires_at)?.toISOString().slice(0, 10) || ''
}
async function submitEdit() {
  const k = edit.value!
  const body = {
    user: k.user,
    label: editF.label,
    expires_at: editF.expires ? new Date(editF.expires + 'T23:59:59').toISOString() : '',
  }
  if ((await run(() => api.patch(`/ssh/keys/${encodeURIComponent(k.fingerprint)}`, body), 'Key updated')) === undefined)
    return
  edit.value = null
  refresh()
}

// revoke: risky, so dry-run first
const revoke = ref<SSHKey | null>(null)
const revokeOpen = computed({
  get: () => !!revoke.value,
  set: v => {
    if (!v) revoke.value = null
  },
})
const revokePath = computed(() => `/ssh/keys/${encodeURIComponent(revoke.value?.fingerprint || '')}`)
const revokeImpact = computed(() => {
  const k = revoke.value
  if (!k) return []
  const left = (data.value || []).filter(x => x.user === k.user && x.fingerprint !== k.fingerprint).length
  const out = [
    `Removes this key from ${k.user}'s authorized_keys. Anyone using it can no longer log in as ${k.user}.`,
    'Existing sessions stay open; kill them under Sessions if needed.',
  ]
  if (!left)
    out.push(`This is the last key for ${k.user}. Without password login, nobody can log in as ${k.user} with a key.`)
  return out
})
// DELETE /ssh/keys has no dry run: the diff is built from the inventory line (file:line from GET /ssh/keys)
async function revokePreview() {
  const k = revoke.value!
  const line = [k.options, k.public_key || `${k.type} ${k.fingerprint}`].filter(Boolean).join(' ')
  return { diff: `--- ${k.file || `~${k.user}/.ssh/authorized_keys`}\n@@ line ${k.line || '?'} @@\n- ${line}` }
}
</script>

<template>
  <div class="flex flex-wrap items-center gap-2">
    <div class="w-44"><FormSelect v-model="userFilter" :options="users" label="Filter by user" /></div>
    <Button v-if="can('ssh:write')" class="ml-auto" @click="addOpen = true">Add key</Button>
  </div>

  <Card>
    <CardContent>
      <LoadState :pending="pending" :error="error" :empty="!rows.length" empty-text="No authorized keys to show. Add a key to grant SSH access.">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>User</TableHead>
              <TableHead>Label / comment</TableHead>
              <TableHead>Type</TableHead>
              <TableHead>Fingerprint</TableHead>
              <TableHead>Last used</TableHead>
              <TableHead>Expires</TableHead>
              <TableHead>Flags</TableHead>
              <TableHead><span class="sr-only">Actions</span></TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            <TableRow v-for="k in rows" :key="k.user + k.fingerprint">
              <TableCell>{{ k.user }}</TableCell>
              <TableCell class="max-w-56">
                <div class="truncate font-medium">{{ k.label || k.owner_person || '-' }}</div>
                <div class="truncate text-xs text-muted-foreground">{{ k.comment }}</div>
              </TableCell>
              <TableCell class="whitespace-nowrap">
                {{ k.type }}
                <span v-if="k.bits" class="text-muted-foreground">{{ k.bits }}</span>
              </TableCell>
              <TableCell class="max-w-48 truncate font-mono text-xs" :title="k.fingerprint">
                {{ k.fingerprint }}
              </TableCell>
              <TableCell>{{ ago(k.last_used_at) }}</TableCell>
              <TableCell>{{ when(k.expires_at)?.toLocaleDateString() || 'never' }}</TableCell>
              <TableCell>
                <div class="flex flex-wrap gap-1">
                  <Badge
                    v-for="f in flags(k)"
                    :key="f"
                    variant="outline"
                    :class="f === 'no owner label' ? 'border-warn/40 text-warn' : 'border-crit/40 text-crit'"
                  >
                    {{ f }}
                  </Badge>
                  <span v-if="!flags(k).length" class="text-xs text-muted-foreground">ok</span>
                </div>
              </TableCell>
              <TableCell class="whitespace-nowrap text-right">
                <template v-if="can('ssh:write')">
                  <Button variant="ghost" size="sm" @click="openEdit(k)">Edit</Button>
                  <Button variant="outline" size="sm" @click="revoke = k">Revoke</Button>
                </template>
              </TableCell>
            </TableRow>
          </TableBody>
        </Table>
      </LoadState>
    </CardContent>
  </Card>

  <Dialog v-model:open="addOpen">
    <DialogContent>
      <DialogHeader>
        <DialogTitle>Add SSH key</DialogTitle>
        <DialogDescription>
          The key is appended to the user's authorized_keys. An expiry removes it automatically.
        </DialogDescription>
      </DialogHeader>
      <form class="space-y-4" @submit.prevent="submitAdd">
        <div class="space-y-1.5">
          <Label for="ak-user">Login user</Label>
          <Input id="ak-user" v-model="add.user" required />
        </div>
        <Tabs v-model="add.source">
          <TabsList aria-label="Key source">
            <TabsTrigger value="paste">Paste key</TabsTrigger>
            <TabsTrigger value="github">GitHub</TabsTrigger>
            <TabsTrigger value="gitlab">GitLab</TabsTrigger>
          </TabsList>
          <TabsContent value="paste" class="space-y-1.5">
            <Label for="ak-key">Public key</Label>
            <Textarea
              id="ak-key"
              v-model="add.key"
              rows="4"
              class="font-mono text-xs"
              placeholder="ssh-ed25519 AAAA… user@laptop"
              :required="add.source === 'paste'"
            />
          </TabsContent>
          <TabsContent v-for="s in ['github', 'gitlab']" :key="s" :value="s" class="space-y-1.5">
            <Label :for="`ak-${s}`">{{ s === 'github' ? 'GitHub' : 'GitLab' }} username</Label>
            <Input :id="`ak-${s}`" v-model="add.handle" :required="add.source === s" placeholder="budi-dev" />
            <p class="text-xs text-muted-foreground">Imports every key from https://{{ s }}.com/&lt;user&gt;.keys</p>
          </TabsContent>
        </Tabs>
        <div class="grid gap-4 sm:grid-cols-2">
          <div class="space-y-1.5">
            <Label for="ak-label">Owner label</Label>
            <Input id="ak-label" v-model="add.label" placeholder="budi laptop" />
          </div>
          <div class="space-y-1.5">
            <Label for="ak-exp">Expires (optional)</Label>
            <Input id="ak-exp" v-model="add.expires" type="date" />
          </div>
        </div>
        <DialogFooter><Button type="submit">Add key</Button></DialogFooter>
      </form>
    </DialogContent>
  </Dialog>

  <Dialog
    :open="!!edit"
    @update:open="
      (v: boolean) => {
        if (!v) edit = null
      }
    "
  >
    <DialogContent>
      <DialogHeader>
        <DialogTitle>Edit key</DialogTitle>
        <DialogDescription class="break-all font-mono text-xs">{{ edit?.fingerprint }}</DialogDescription>
      </DialogHeader>
      <form class="space-y-4" @submit.prevent="submitEdit">
        <div class="space-y-1.5">
          <Label for="ek-label">Owner label</Label>
          <Input id="ek-label" v-model="editF.label" />
        </div>
        <div class="space-y-1.5">
          <Label for="ek-exp">Expires</Label>
          <Input id="ek-exp" v-model="editF.expires" type="date" />
        </div>
        <DialogFooter><Button type="submit">Save</Button></DialogFooter>
      </form>
    </DialogContent>
  </Dialog>

  <RiskDialog
    v-model:open="revokeOpen"
    :title="`Revoke key for ${revoke?.user}`"
    confirm="Revoke key"
    :impact="revokeImpact"
    :preview="revokePreview"
    :apply="() => api.del(revokePath, { query: { user: revoke!.user } })"
    @done="
      () => {
        toast.success('Key revoked')
        refresh()
      }
    "
  >
    <p class="text-sm">
      <span class="font-medium">{{ revoke?.label || revoke?.comment }}</span>
      <span class="block break-all font-mono text-xs text-muted-foreground">{{ revoke?.fingerprint }}</span>
    </p>
  </RiskDialog>
</template>
