<script setup lang="ts">
import { toast } from 'vue-sonner'
import type { Fix } from '~/types/models'

const live = useLive()
const { data, pending, error, refresh } = useAsyncData('harden.fixes', async () =>
  list<Fix>(await api.get('/harden/fixes'), 'fixes'),
)
watch(
  () => live.tick.value.harden,
  () => refresh(),
)
defineExpose({ refresh })

const sel = ref<Fix | null>(null)
const open = computed({
  get: () => !!sel.value,
  set: v => {
    if (!v) sel.value = null
  },
})
// revert restores the backup taken before the fix: show the fix diff inverted
const inverted = computed(() =>
  (sel.value?.diff || '')
    .split('\n')
    .map(l => {
      if (l.startsWith('+') && !l.startsWith('+++')) return '-' + l.slice(1)
      if (l.startsWith('-') && !l.startsWith('---')) return '+' + l.slice(1)
      return l
    })
    .join('\n'),
)
</script>

<template>
  <Card>
    <CardContent>
      <LoadState :pending="pending" :error="error" :empty="!data?.length" empty-text="No fixes applied yet.">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Applied</TableHead>
              <TableHead>Check</TableHead>
              <TableHead>By</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Reverted</TableHead>
              <TableHead><span class="sr-only">Actions</span></TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            <TableRow v-for="f in data" :key="f.id">
              <TableCell class="whitespace-nowrap">{{ fmtDate(f.applied_at) }}</TableCell>
              <TableCell class="font-mono">{{ f.check_id }}</TableCell>
              <TableCell>{{ f.applied_by }}</TableCell>
              <TableCell><StateBadge :value="when(f.reverted_at) ? 'reverted' : f.status || 'applied'" /></TableCell>
              <TableCell>{{ fmtDate(f.reverted_at) }}</TableCell>
              <TableCell class="text-right">
                <Button v-if="can('harden:write') && !when(f.reverted_at)" variant="outline" size="sm" @click="sel = f">
                  Revert
                </Button>
              </TableCell>
            </TableRow>
          </TableBody>
        </Table>
      </LoadState>
    </CardContent>
  </Card>

  <RiskDialog
    v-model:open="open"
    :title="`Revert fix ${sel?.check_id}`"
    confirm="Revert fix"
    :impact="[`Restores the backup taken before fix ${sel?.id}. The check ${sel?.check_id} will likely fail again.`]"
    :preview="async () => ({ diff: inverted })"
    :apply="() => api.post(`/harden/fixes/${sel!.id}/revert`)"
    @done="
      () => {
        toast.success('Fix reverted')
        refresh()
      }
    "
  />
</template>
