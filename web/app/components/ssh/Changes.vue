<script setup lang="ts">
import type { SSHChange } from '~/types/models'

const live = useLive()
const { data, pending, error, refresh } = useAsyncData('ssh.changes', async () =>
  list<SSHChange>(await api.get('/ssh/changes'), 'changes'),
)
watch(
  () => live.tick.value.ssh,
  () => refresh(),
)
</script>

<template>
  <LoadState :pending="pending" :error="error" :empty="!data?.length" empty-text="No sshd changes recorded.">
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>When</TableHead>
          <TableHead>Actor</TableHead>
          <TableHead>Setting</TableHead>
          <TableHead>Old</TableHead>
          <TableHead>New</TableHead>
          <TableHead>Status</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        <TableRow v-for="c in data" :key="c.id">
          <TableCell class="whitespace-nowrap">{{ fmtDate(c.ts) }}</TableCell>
          <TableCell>{{ c.actor }}</TableCell>
          <TableCell class="font-mono">{{ c.setting }}</TableCell>
          <TableCell class="max-w-48 break-all font-mono text-xs">{{ c.old_value || '(unset)' }}</TableCell>
          <TableCell class="max-w-48 break-all font-mono text-xs">{{ c.new_value }}</TableCell>
          <TableCell><StateBadge :value="c.status" /></TableCell>
        </TableRow>
      </TableBody>
    </Table>
  </LoadState>
</template>
