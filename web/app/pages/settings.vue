<script setup lang="ts">
import QRCode from 'qrcode'
import { toast } from 'vue-sonner'
import type { APIToken, User } from '~/types/models'

useHead({ title: 'Settings · ServerKeeper' })
const tab = useTab('users')
const admin = computed(() => can('admin'))

// users
const {
  data: users,
  pending: uPending,
  error: uErr,
  refresh: refreshUsers,
} = useAsyncData('users', async () => (admin.value ? list<User>(await api.get('/users')) : []))
const uOpen = ref(false)
const u = reactive({ username: '', password: '', role: 'operator' })
const enroll = ref<{ user: string; url: string; qr: string } | null>(null)
async function createUser() {
  const r = await run(() => api.post('/users', { ...u }), 'User created')
  if (!r) return
  uOpen.value = false
  if (r.totp_url)
    enroll.value = {
      user: u.username,
      url: r.totp_url,
      qr: await QRCode.toDataURL(r.totp_url, { margin: 1, width: 220 }),
    }
  Object.assign(u, { username: '', password: '' })
  refreshUsers()
}
async function delUser(x: User) {
  await run(() => api.del('/users/{id}', { path: { id: x.id } }), 'User deleted')
  refreshUsers()
}
async function unlock(x: User) {
  await run(() => api.post('/users/{name}/unlock', undefined, { path: { name: x.username } }), 'User unlocked')
  refreshUsers()
}

// tokens
const SCOPES = ['read', 'ssh:write', 'harden:write', 'admin'] as const
const {
  data: tokens,
  pending: tPending,
  error: tErr,
  refresh: refreshTokens,
} = useAsyncData('tokens', async () => (admin.value ? list<APIToken>(await api.get('/tokens')) : []))
const tOpen = ref(false)
const t = reactive({ name: '', scopes: ['read'] as string[], ttl: '' })
const created = ref('')
function toggleScope(s: string, on: boolean | 'indeterminate') {
  t.scopes = on === true ? [...t.scopes, s] : t.scopes.filter(x => x !== s)
}
async function createToken() {
  const r = await run(() => api.post('/tokens', { name: t.name, scopes: t.scopes, ttl: t.ttl || undefined }))
  if (!r) return
  tOpen.value = false
  created.value = r.token || ''
  Object.assign(t, { name: '', scopes: ['read'], ttl: '' })
  refreshTokens()
}
async function revokeToken(x: APIToken) {
  await run(() => api.del('/tokens/{id}', { path: { id: x.id } }), 'Token revoked')
  refreshTokens()
}
async function copy(s: string) {
  await run(() => navigator.clipboard.writeText(s), 'Copied')
}

// about
const { data: health } = useAsyncData('health', () => api.get('/health'))
const { data: status } = useAsyncData('status', () => api.get('/status'))

// backup: SQLite + agent store (+ VictoriaMetrics snapshot on central) into the configured destination
const backing = ref(false)
const lastBackup = ref<{ path?: string, manifest?: { files?: Record<string, string> } } | null>(null)
async function backup() {
  backing.value = true
  const r = await run(() => api.post('/backup', {}), 'Backup written')
  backing.value = false
  if (r) lastBackup.value = r
}

// storage: data_dir usage and metric history cleanup (agent store only)
const {
  data: storage,
  pending: sPending,
  error: sErr,
  refresh: refreshStorage,
} = useAsyncData('storage', () => api.get('/storage'), { lazy: true })
const olderThan = ref('7d')
const CUTOFFS = [
  { value: '1h', label: 'Older than 1 hour' },
  { value: '6h', label: 'Older than 6 hours' },
  { value: '24h', label: 'Older than 24 hours' },
  { value: '7d', label: 'Older than 7 days' },
  { value: '0', label: 'All history' },
]
const cutoffLabel = computed(() => CUTOFFS.find(c => c.value === olderThan.value)?.label.toLowerCase())
async function clearHistory() {
  const r = await run(() => api.post('/storage/history/clear', { older_than: olderThan.value }))
  if (r) toast.success(`History cleared, ${bytes(r.freed_bytes)} freed`)
  refreshStorage()
}

// uninstall: runs `serverkeeper uninstall` as root 3 s after the response
const purge = ref(false)
const confirmName = ref('')
const uninstalling = ref(false)
async function uninstall() {
  const r = await run(() => api.post('/uninstall', { confirm: confirmName.value, purge: purge.value }))
  if (r) uninstalling.value = true
}
</script>

<template>
  <h1 class="text-2xl font-semibold">Settings</h1>
  <Tabs v-model="tab">
    <TabsList>
      <TabsTrigger value="users">Users</TabsTrigger>
      <TabsTrigger value="tokens">API tokens</TabsTrigger>
      <TabsTrigger value="storage">Storage</TabsTrigger>
      <TabsTrigger value="about">About</TabsTrigger>
    </TabsList>

    <TabsContent value="users" class="space-y-3">
      <p v-if="!admin" class="text-sm text-muted-foreground">Managing users needs the admin role.</p>
      <template v-else>
        <div class="flex"><Button class="ml-auto" @click="uOpen = true">New user</Button></div>
        <LoadState :pending="uPending" :error="uErr" :empty="!users?.length">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Username</TableHead>
                <TableHead>Role</TableHead>
                <TableHead>2FA</TableHead>
                <TableHead>Locked</TableHead>
                <TableHead>Created</TableHead>
                <TableHead class="sr-only">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              <TableRow v-for="x in users" :key="x.id">
                <TableCell class="font-medium">{{ x.username }}</TableCell>
                <TableCell class="capitalize">{{ x.role }}</TableCell>
                <TableCell><StateBadge :value="x.totp_enabled ? 'active' : 'pending'" /></TableCell>
                <TableCell>
                  {{ (when(x.locked_until)?.getTime() ?? 0) > Date.now() ? `until ${fmtDate(x.locked_until)}` : 'no' }}
                </TableCell>
                <TableCell>{{ fmtDate(x.created_at) }}</TableCell>
                <TableCell class="whitespace-nowrap text-right">
                  <Button v-if="x.failed_logins || when(x.locked_until)" variant="ghost" size="sm" @click="unlock(x)">
                    Unlock
                  </Button>
                  <ConfirmButton
                    :title="`Delete user ${x.username}?`"
                    confirm="Delete"
                    :disabled="x.username === useMe().value?.actor"
                    description="Their sessions end and they can no longer sign in."
                    :action="() => delUser(x)"
                  >
                    Delete
                  </ConfirmButton>
                </TableCell>
              </TableRow>
            </TableBody>
          </Table>
        </LoadState>
      </template>
    </TabsContent>

    <TabsContent value="tokens" class="space-y-3">
      <p v-if="!admin" class="text-sm text-muted-foreground">Managing API tokens needs the admin role.</p>
      <template v-else>
        <div class="flex"><Button class="ml-auto" @click="tOpen = true">New token</Button></div>
        <LoadState :pending="tPending" :error="tErr" :empty="!tokens?.length">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Scopes</TableHead>
                <TableHead>Created</TableHead>
                <TableHead>Expires</TableHead>
                <TableHead>Last used</TableHead>
                <TableHead class="sr-only">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              <TableRow v-for="x in tokens" :key="x.id">
                <TableCell class="font-medium">{{ x.name }}</TableCell>
                <TableCell>
                  <Badge v-for="s in x.scopes" :key="s" variant="secondary" class="mr-1">{{ s }}</Badge>
                </TableCell>
                <TableCell>
                  {{ fmtDate(x.created_at) }}
                  <span class="text-xs text-muted-foreground">by {{ x.created_by }}</span>
                </TableCell>
                <TableCell>{{ when(x.expires_at) ? fmtDate(x.expires_at) : 'never' }}</TableCell>
                <TableCell>{{ ago(x.last_used_at) }}</TableCell>
                <TableCell class="text-right">
                  <ConfirmButton
                    :title="`Revoke token ${x.name}?`"
                    confirm="Revoke"
                    description="Scripts and CLIs using this token stop working immediately."
                    :action="() => revokeToken(x)"
                  >
                    Revoke
                  </ConfirmButton>
                </TableCell>
              </TableRow>
            </TableBody>
          </Table>
        </LoadState>
      </template>
    </TabsContent>

    <TabsContent value="storage" class="space-y-4">
      <LoadState :pending="sPending" :error="sErr" :empty="!storage">
        <Card>
          <CardHeader>
            <CardTitle>Disk usage</CardTitle>
            <CardDescription>
              {{ bytes(storage?.total_bytes) }} in <span class="font-mono">{{ storage?.data_dir }}</span>
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Path</TableHead>
                  <TableHead class="text-right">Size</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                <TableRow v-for="e in storage?.entries" :key="e.path">
                  <TableCell class="font-medium">{{ e.name }}{{ e.dir ? '/' : '' }}</TableCell>
                  <TableCell class="font-mono text-xs text-muted-foreground">{{ e.path }}</TableCell>
                  <TableCell class="text-right tabular-nums">{{ bytes(e.bytes) }}</TableCell>
                </TableRow>
              </TableBody>
            </Table>
          </CardContent>
        </Card>

        <Card v-if="storage?.agent_store">
          <CardHeader>
            <CardTitle>Metric history (agent.db)</CardTitle>
            <CardDescription>
              {{ bytes(storage.agent_store.file_bytes) }} on disk,
              {{ bytes(storage.agent_store.reclaimable_bytes) }} free inside the file.
              Raw samples since {{ fmtDate(storage.agent_store.raw_oldest) }},
              1-minute rollups since {{ fmtDate(storage.agent_store.rollup_oldest) }}.
            </CardDescription>
          </CardHeader>
          <CardContent class="space-y-4">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Bucket</TableHead>
                  <TableHead class="text-right">Keys</TableHead>
                  <TableHead class="text-right">Size</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                <TableRow v-for="b in storage.agent_store.buckets" :key="b.name">
                  <TableCell class="font-mono">{{ b.name }}</TableCell>
                  <TableCell class="text-right tabular-nums">{{ num(b.keys) }}</TableCell>
                  <TableCell class="text-right tabular-nums">{{ bytes(b.bytes) }}</TableCell>
                </TableRow>
              </TableBody>
            </Table>
            <div v-if="admin && !useFleet().value" class="flex flex-wrap items-end gap-2">
              <div class="space-y-1">
                <Label for="st-cut">Delete graph history</Label>
                <FormSelect id="st-cut" v-model="olderThan" :options="CUTOFFS" />
              </div>
              <ConfirmButton
                :title="`Delete metric history ${cutoffLabel}?`"
                confirm="Delete"
                variant="destructive"
                size="default"
                description="Graphs lose this range permanently. The store file is then compacted to free disk space."
                :action="clearHistory"
              >
                Delete and compact
              </ConfirmButton>
            </div>
          </CardContent>
        </Card>
      </LoadState>
    </TabsContent>

    <TabsContent value="about">
      <Card>
        <CardContent>
          <dl class="grid grid-cols-[auto_1fr] gap-x-6 gap-y-2 text-sm">
            <dt class="text-muted-foreground">Version</dt>
            <dd class="font-mono">{{ health?.version || status?.version || '—' }}</dd>
            <dt class="text-muted-foreground">Server</dt>
            <dd>{{ status?.server_name || '—' }}</dd>
            <dt class="text-muted-foreground">Mode</dt>
            <dd>{{ useFleet().value ? 'Central server (fleet)' : 'Agent (single server)' }}</dd>
            <dt class="text-muted-foreground">Signed in as</dt>
            <dd>{{ useMe().value?.actor }} ({{ useMe().value?.scopes.join(', ') }})</dd>
            <dt class="text-muted-foreground">API</dt>
            <dd><a class="underline underline-offset-4" href="/api/v1/openapi.yaml">OpenAPI spec</a></dd>
          </dl>
        </CardContent>
      </Card>
      <Card v-if="admin" class="mt-4">
        <CardHeader>
          <CardTitle>Backup</CardTitle>
          <CardDescription>Copies the database and metrics store to the backup destination in config.yaml.</CardDescription>
        </CardHeader>
        <CardContent class="space-y-2 text-sm">
          <Button :disabled="backing" @click="backup">{{ backing ? 'Backing up…' : 'Back up now' }}</Button>
          <p v-if="lastBackup">
            Written to <span class="font-mono">{{ lastBackup.path }}</span>
            ({{ Object.keys(lastBackup.manifest?.files || {}).length }} files)
          </p>
        </CardContent>
      </Card>
      <Card v-if="admin && !useFleet().value" class="mt-4 border-destructive">
        <CardHeader>
          <CardTitle>Uninstall</CardTitle>
          <CardDescription>
            Stops ServerKeeper and removes its units and binary from this server. Data and config are kept unless
            you purge them. The sshd drop-in and hardening changes are left in place.
          </CardDescription>
        </CardHeader>
        <CardContent class="space-y-3 text-sm">
          <p v-if="uninstalling" role="status">Uninstalling. This page stops responding in a few seconds.</p>
          <template v-else>
            <label class="flex items-center gap-2">
              <Switch v-model="purge" />
              Also delete data, config and the serverkeeper user
            </label>
            <div class="space-y-1">
              <Label for="un-name">Type the server name ({{ status?.server_name }}) to confirm</Label>
              <Input id="un-name" v-model="confirmName" autocomplete="off" class="max-w-xs" />
            </div>
            <ConfirmButton
              :title="`Uninstall ServerKeeper from ${status?.server_name}?`"
              confirm="Uninstall"
              variant="destructive"
              size="default"
              :disabled="!status?.server_name || confirmName !== status?.server_name"
              :description="
                purge
                  ? 'All metrics, users, audit log and config are deleted. This cannot be undone.'
                  : 'Monitoring, alerts and SSH key management stop on this server.'
              "
              :action="uninstall"
            >
              Uninstall
            </ConfirmButton>
          </template>
        </CardContent>
      </Card>
    </TabsContent>
  </Tabs>

  <Dialog v-model:open="uOpen">
    <DialogContent>
      <DialogHeader>
        <DialogTitle>New user</DialogTitle>
        <DialogDescription>TOTP is mandatory. The enrollment QR code is shown once after creation.</DialogDescription>
      </DialogHeader>
      <form class="space-y-3" @submit.prevent="createUser">
        <div class="space-y-1">
          <Label for="nu-name">Username</Label>
          <Input id="nu-name" v-model="u.username" required autocomplete="off" />
        </div>
        <div class="space-y-1">
          <Label for="nu-pw">Password</Label>
          <Input id="nu-pw" v-model="u.password" type="password" required minlength="12" autocomplete="new-password" />
          <p class="text-xs text-muted-foreground">At least 12 characters.</p>
        </div>
        <div class="space-y-1">
          <Label for="nu-role">Role</Label>
          <FormSelect
            id="nu-role"
            v-model="u.role"
            :options="[
              { value: 'admin', label: 'Admin: everything' },
              { value: 'operator', label: 'Operator: read, SSH and hardening changes' },
              { value: 'viewer', label: 'Viewer: read only' },
            ]"
          />
        </div>
        <DialogFooter><Button type="submit">Create user</Button></DialogFooter>
      </form>
    </DialogContent>
  </Dialog>

  <Dialog
    :open="!!enroll"
    @update:open="
      (v: boolean) => {
        if (!v) enroll = null
      }
    "
  >
    <DialogContent>
      <DialogHeader>
        <DialogTitle>Set up 2FA for {{ enroll?.user }}</DialogTitle>
        <DialogDescription>Scan with an authenticator app. This code is not shown again.</DialogDescription>
      </DialogHeader>
      <img
        v-if="enroll"
        :src="enroll.qr"
        alt="TOTP enrollment QR code"
        width="220"
        height="220"
        class="mx-auto rounded bg-white p-2"
      />
      <div class="flex gap-2">
        <Input :model-value="enroll?.url" readonly aria-label="TOTP URL" class="font-mono text-xs" />
        <Button variant="outline" @click="copy(enroll!.url)">Copy</Button>
      </div>
    </DialogContent>
  </Dialog>

  <Dialog v-model:open="tOpen">
    <DialogContent>
      <DialogHeader>
        <DialogTitle>New API token</DialogTitle>
        <DialogDescription>Give each script its own token with the fewest scopes it needs.</DialogDescription>
      </DialogHeader>
      <form class="space-y-3" @submit.prevent="createToken">
        <div class="space-y-1">
          <Label for="nt-name">Name</Label>
          <Input id="nt-name" v-model="t.name" required placeholder="ci-deploy" />
        </div>
        <fieldset class="space-y-1">
          <legend class="text-sm font-medium">Scopes</legend>
          <div class="flex flex-wrap gap-3">
            <label v-for="s in SCOPES" :key="s" class="flex items-center gap-2 text-sm">
              <Checkbox :model-value="t.scopes.includes(s)" @update:model-value="v => toggleScope(s, v)" />
              {{ s }}
            </label>
          </div>
        </fieldset>
        <div class="space-y-1">
          <Label for="nt-ttl">Expires after (optional)</Label>
          <Input id="nt-ttl" v-model="t.ttl" placeholder="720h" class="w-32" />
          <p class="text-xs text-muted-foreground">Go duration, e.g. 24h or 720h. Empty = never.</p>
        </div>
        <DialogFooter><Button type="submit" :disabled="!t.scopes.length">Create token</Button></DialogFooter>
      </form>
    </DialogContent>
  </Dialog>

  <Dialog
    :open="!!created"
    @update:open="
      (v: boolean) => {
        if (!v) created = ''
      }
    "
  >
    <DialogContent>
      <DialogHeader>
        <DialogTitle>Token created</DialogTitle>
        <DialogDescription>Copy it now. It is stored hashed and cannot be shown again.</DialogDescription>
      </DialogHeader>
      <div class="flex gap-2">
        <Input :model-value="created" readonly aria-label="API token" class="font-mono text-xs" />
        <Button variant="outline" @click="copy(created)">Copy</Button>
      </div>
    </DialogContent>
  </Dialog>
</template>
