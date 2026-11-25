<script setup lang="ts">
const { data: raw, pending, error, refresh } = useAsyncData('ssh.bans', () => api.get('/ssh/bans'))
const data = computed(() => list<any>(raw.value, 'bans'))
const backend = computed(() => (raw.value as any)?.backend as string | undefined)
async function unban(ip: string) {
  await run(() => api.del(`/ssh/bans/${encodeURIComponent(ip)}`), `${ip} unbanned`)
  refresh()
}

// manual ban dialog
const DURATIONS = [
  { value: '1h', label: '1 hour' },
  { value: '24h', label: '24 hours' },
  { value: '7d', label: '7 days' },
  { value: '30d', label: '30 days' },
]
const banOpen = ref(false)
const form = reactive({ ip: '', duration: '24h', reason: '' })
async function submitBan() {
  const ip = form.ip.trim()
  const r = await run(() => api.post('/ssh/bans', { ip, duration: form.duration, reason: form.reason }), `${ip} banned`)
  if (r === undefined) return
  banOpen.value = false
  Object.assign(form, { ip: '', duration: '24h', reason: '' })
  refresh()
}
</script>

<template>
  <div class="mb-2 flex flex-wrap items-center gap-2">
    <p v-if="backend" class="text-sm text-muted-foreground">Firewall backend: {{ backend }}</p>
    <Button v-if="can('ssh:write')" class="ml-auto" @click="banOpen = true">Ban IP</Button>
  </div>
  <Card>
    <CardContent>
      <LoadState
        :pending="pending"
        :error="error"
        :empty="!data?.length"
        empty-text="No active bans. Addresses appear here when the SSH brute-force ban or the DDoS auto-ban (when enabled) blocks them, or when you ban one with Ban IP."
      >
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>IP</TableHead>
              <TableHead>Reason</TableHead>
              <TableHead>Banned</TableHead>
              <TableHead>Expires</TableHead>
              <TableHead><span class="sr-only">Actions</span></TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            <TableRow v-for="b in data" :key="b.ip">
              <TableCell class="font-mono">{{ b.ip }}</TableCell>
              <TableCell>{{ b.reason }}</TableCell>
              <TableCell>{{ ago(b.created_at) }}</TableCell>
              <TableCell>{{ when(b.expires_at) ? ago(b.expires_at) : 'never' }}</TableCell>
              <TableCell class="text-right">
                <ConfirmButton
                  v-if="can('ssh:write')"
                  :title="`Unban ${b.ip}?`"
                  confirm="Unban"
                  description="The firewall rule is removed and this IP can connect again."
                  :action="() => unban(b.ip)"
                >
                  Unban
                </ConfirmButton>
              </TableCell>
            </TableRow>
          </TableBody>
        </Table>
      </LoadState>
    </CardContent>
  </Card>

  <Dialog v-model:open="banOpen">
    <DialogContent>
      <DialogHeader>
        <DialogTitle>Ban IP</DialogTitle>
        <DialogDescription>
          The host firewall drops all traffic from this address until the ban expires. Loopback addresses,
          allowlisted addresses and your own address are refused.
        </DialogDescription>
      </DialogHeader>
      <form class="space-y-4" @submit.prevent="submitBan">
        <div class="space-y-1.5">
          <Label for="ban-ip">IP address</Label>
          <Input id="ban-ip" v-model="form.ip" class="font-mono" placeholder="IPv4 or IPv6 address" required />
        </div>
        <div class="grid gap-4 sm:grid-cols-2">
          <div class="space-y-1.5">
            <Label for="ban-for">Duration</Label>
            <FormSelect id="ban-for" v-model="form.duration" :options="DURATIONS" label="Duration" />
          </div>
          <div class="space-y-1.5">
            <Label for="ban-reason">Reason (optional)</Label>
            <Input id="ban-reason" v-model="form.reason" maxlength="200" placeholder="Why this address is banned" />
          </div>
        </div>
        <DialogFooter><Button type="submit">Ban IP</Button></DialogFooter>
      </form>
    </DialogContent>
  </Dialog>
</template>
