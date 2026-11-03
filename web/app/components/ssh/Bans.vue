<script setup lang="ts">
const { data: raw, pending, error, refresh } = useAsyncData('ssh.bans', () => api.get('/ssh/bans'))
const data = computed(() => list<any>(raw.value, 'bans'))
const backend = computed(() => (raw.value as any)?.backend as string | undefined)
async function unban(ip: string) {
  await run(() => api.del(`/ssh/bans/${encodeURIComponent(ip)}`), `${ip} unbanned`)
  refresh()
}
</script>

<template>
  <p v-if="backend" class="mb-2 text-sm text-muted-foreground">Firewall backend: {{ backend }}</p>
  <LoadState :pending="pending" :error="error" :empty="!data?.length" empty-text="No banned IPs.">
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>IP</TableHead>
          <TableHead>Reason</TableHead>
          <TableHead>Banned</TableHead>
          <TableHead>Expires</TableHead>
          <TableHead class="sr-only">Actions</TableHead>
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
              description="The firewall rule is removed and this IP can try to log in again."
              :action="() => unban(b.ip)"
            >
              Unban
            </ConfirmButton>
          </TableCell>
        </TableRow>
      </TableBody>
    </Table>
  </LoadState>
</template>
