<script setup lang="ts">
// session rows from GET /ssh/sessions; field names tolerated loosely until the spec is final
defineProps<{ rows: any[] }>()
const emit = defineEmits<{ kill: [pid: number] }>()
</script>

<template>
  <Table>
    <TableHeader>
      <TableRow>
        <TableHead>User</TableHead>
        <TableHead>From</TableHead>
        <TableHead>TTY</TableHead>
        <TableHead>Started</TableHead>
        <TableHead>PID</TableHead>
        <TableHead><span class="sr-only">Actions</span></TableHead>
      </TableRow>
    </TableHeader>
    <TableBody>
      <TableRow v-for="s in rows" :key="s.pid">
        <TableCell>{{ s.user }}</TableCell>
        <TableCell class="font-mono">{{ s.ip || s.from || s.source_ip || '-' }}</TableCell>
        <TableCell>{{ s.tty || '-' }}</TableCell>
        <TableCell>{{ fmtDate(s.started_at || s.start || s.started) }}</TableCell>
        <TableCell class="tabular-nums">{{ s.pid }}</TableCell>
        <TableCell class="text-right">
          <ConfirmButton
            v-if="can('ssh:write')"
            :title="`Kill session ${s.pid}?`"
            confirm="Kill session"
            :description="`${s.user} from ${s.ip || s.from || 'unknown'} is disconnected immediately. Unsaved work is lost.`"
            :action="async () => emit('kill', s.pid)"
          >
            Kill
          </ConfirmButton>
        </TableCell>
      </TableRow>
      <TableEmpty v-if="!rows.length" :colspan="6">No active sessions.</TableEmpty>
    </TableBody>
  </Table>
</template>
