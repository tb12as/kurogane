<script setup lang="ts">
interface ChannelInfo { name: string, type: string, has_secret: boolean, webhook_url_env?: string, source: string, ready: boolean }

const { data, pending, error, refresh } = useAsyncData('alerts.channels', async () =>
  list<ChannelInfo>(await api.get('/alerts/channels')),
)
const admin = computed(() => can('admin'))
const TYPES = ['slack', 'discord', 'telegram', 'email', 'pagerduty', 'webhook']
const SECRET: Record<string, { label: string, hint: string }> = {
  slack: { label: 'Webhook URL', hint: 'https://hooks.slack.com/services/…' },
  discord: { label: 'Webhook URL', hint: 'https://discord.com/api/webhooks/…' },
  webhook: { label: 'Webhook URL', hint: 'https://example.com/hooks/kurogane' },
  telegram: { label: 'Bot API URL', hint: 'https://api.telegram.org/bot<token>' },
  pagerduty: { label: 'Routing key', hint: 'Events API v2 integration key' },
  email: { label: 'SMTP password', hint: 'leave empty when the server needs no login' },
}

const open = ref(false)
const blank = () => ({ name: '', kind: 'slack', secret: '', env: '', chat: '', smtp: '', user: '', from: '', to: '' })
const cf = reactive(blank())
const sec = computed(() => SECRET[cf.kind]!)

async function save() {
  // secrets are sealed server-side and never shown again (AL-8); the body is decoded strictly
  const body: Record<string, unknown> = { name: cf.name, type: cf.kind }
  if (cf.env) body.webhook_url_env = cf.env
  else if (cf.secret) body.webhook_url = cf.secret
  if (cf.kind === 'telegram') body.chat_id = cf.chat
  if (cf.kind === 'email') {
    Object.assign(body, { smtp_addr: cf.smtp, smtp_user: cf.user, from: cf.from })
    body.to = cf.to.split(',').map(s => s.trim()).filter(Boolean)
  }
  if ((await run(() => api.post('/alerts/channels', body), 'Channel added')) === undefined) return
  open.value = false
  Object.assign(cf, blank())
  refresh()
}
const test = (c: ChannelInfo) =>
  run(() => api.post(`/alerts/channels/${encodeURIComponent(c.name)}/test`), `Test message sent to ${c.name}`)
async function del(c: ChannelInfo) {
  await run(() => api.del(`/alerts/channels/${encodeURIComponent(c.name)}`), 'Channel deleted')
  refresh()
}
</script>

<template>
  <div class="flex"><Button v-if="admin" class="ml-auto" @click="open = true">Add channel</Button></div>
  <Card>
    <CardContent>
      <LoadState
        :pending="pending"
        :error="error"
        :empty="!data?.length"
        empty-text="No channels. Add a Slack or Discord webhook to receive alerts."
      >
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Name</TableHead>
              <TableHead>Type</TableHead>
              <TableHead>Secret</TableHead>
              <TableHead>Defined in</TableHead>
              <TableHead>State</TableHead>
              <TableHead><span class="sr-only">Actions</span></TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            <TableRow v-for="c in data" :key="c.name">
              <TableCell class="font-medium">{{ c.name }}</TableCell>
              <TableCell class="capitalize">{{ c.type }}</TableCell>
              <TableCell class="text-xs">
                <span v-if="c.webhook_url_env" class="font-mono">env {{ c.webhook_url_env }}</span>
                <span v-else>{{ c.has_secret ? 'stored encrypted' : 'none' }}</span>
              </TableCell>
              <TableCell>{{ c.source === 'config' ? 'config.yaml' : 'API / UI' }}</TableCell>
              <TableCell><StateBadge :value="c.ready ? 'ready' : 'not ready'" /></TableCell>
              <TableCell class="whitespace-nowrap text-right">
                <Button v-if="admin" variant="outline" size="sm" @click="test(c)">Send test</Button>
                <ConfirmButton
                  v-if="admin && c.source !== 'config'"
                  :title="`Delete channel ${c.name}?`"
                  confirm="Delete"
                  description="Rules routed only to this channel will no longer notify anyone."
                  :action="() => del(c)"
                >
                  Delete
                </ConfirmButton>
              </TableCell>
            </TableRow>
          </TableBody>
        </Table>
      </LoadState>
    </CardContent>
  </Card>

  <Dialog v-model:open="open">
    <DialogScrollContent>
      <DialogHeader>
        <DialogTitle>Add channel</DialogTitle>
        <DialogDescription>Secrets are stored encrypted and never displayed again.</DialogDescription>
      </DialogHeader>
      <form class="space-y-3" @submit.prevent="save">
        <div class="grid gap-3 sm:grid-cols-2">
          <div class="space-y-1">
            <Label for="c-name">Name</Label>
            <Input id="c-name" v-model="cf.name" required placeholder="ops" />
          </div>
          <div class="space-y-1">
            <Label for="c-type">Type</Label>
            <FormSelect id="c-type" v-model="cf.kind" :options="TYPES" />
          </div>
        </div>
        <template v-if="cf.kind === 'email'">
          <div class="grid gap-3 sm:grid-cols-2">
            <div class="space-y-1">
              <Label for="c-smtp">SMTP server</Label>
              <Input id="c-smtp" v-model="cf.smtp" required placeholder="smtp.example.com:587" />
            </div>
            <div class="space-y-1">
              <Label for="c-user">SMTP user</Label>
              <Input id="c-user" v-model="cf.user" autocomplete="off" />
            </div>
            <div class="space-y-1">
              <Label for="c-from">From</Label>
              <Input id="c-from" v-model="cf.from" type="email" required />
            </div>
            <div class="space-y-1">
              <Label for="c-to">To (comma separated)</Label>
              <Input id="c-to" v-model="cf.to" required placeholder="ops@example.com" />
            </div>
          </div>
        </template>
        <div v-if="cf.kind === 'telegram'" class="space-y-1">
          <Label for="c-chat">Chat ID</Label>
          <Input id="c-chat" v-model="cf.chat" required placeholder="-1001234567890" />
        </div>
        <div class="space-y-1">
          <Label for="c-secret">{{ sec.label }}</Label>
          <Input
            id="c-secret"
            v-model="cf.secret"
            :type="cf.kind === 'pagerduty' || cf.kind === 'email' ? 'password' : 'url'"
            :required="cf.kind !== 'email' && !cf.env"
            autocomplete="off"
            :placeholder="sec.hint"
          />
        </div>
        <div class="space-y-1">
          <Label for="c-env">Or read it from an environment variable</Label>
          <Input id="c-env" v-model="cf.env" class="font-mono" placeholder="KRGN_SLACK_OPS" />
          <p class="text-xs text-muted-foreground">Keeps the secret out of the database; set it in the agent's environment.</p>
        </div>
        <DialogFooter><Button type="submit">Add channel</Button></DialogFooter>
      </form>
    </DialogScrollContent>
  </Dialog>
</template>
