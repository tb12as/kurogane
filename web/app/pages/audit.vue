<script setup lang="ts">
import type { AuditEntry } from '~/types/models'

useHead({ title: 'Audit log · ServerKeeper' })
const PAGE = 100
const f = reactive({ actor: '', action: '', since: '24h' })
const q = reactive({ actor: '', action: '', since: '24h' })
const offset = ref(0)
const { data, pending, error } = useAsyncData(
  'audit',
  async () =>
    list<AuditEntry>(
      await api.get('/audit', {
        query: {
          actor: q.actor,
          action: q.action,
          since: q.since === 'all' ? '' : q.since,
          limit: PAGE,
          offset: offset.value,
        },
      }),
    ),
  { watch: [q, offset] },
)
function apply() {
  Object.assign(q, f)
  offset.value = 0
}
const open = ref<Record<number, boolean>>({})
</script>

<template>
  <h1 class="text-2xl font-semibold">Audit log</h1>
  <form class="grid grid-cols-2 gap-2 sm:flex sm:flex-wrap sm:items-end" @submit.prevent="apply">
    <div class="space-y-1">
      <Label for="a-actor">Actor</Label>
      <Input id="a-actor" v-model="f.actor" placeholder="Any user" />
    </div>
    <div class="space-y-1">
      <Label for="a-action">Action starts with</Label>
      <Input id="a-action" v-model="f.action" placeholder="For example ssh." />
    </div>
    <div class="space-y-1 sm:w-36">
      <Label for="a-since">Since</Label>
      <FormSelect
        id="a-since"
        v-model="f.since"
        :options="[
          { value: '1h', label: 'Last hour' },
          { value: '24h', label: 'Last 24 h' },
          { value: '168h', label: 'Last 7 days' },
          { value: '720h', label: 'Last 30 days' },
          { value: 'all', label: 'All time' },
        ]"
      />
    </div>
    <Button type="submit">Filter</Button>
  </form>

  <Card>
    <CardContent>
      <LoadState :pending="pending" :error="error" :empty="!data?.length" empty-text="No audit entries match.">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead class="w-8"><span class="sr-only">Details</span></TableHead>
              <TableHead>When</TableHead>
              <TableHead>Actor</TableHead>
              <TableHead>Action</TableHead>
              <TableHead>Target</TableHead>
              <TableHead>Source IP</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            <template v-for="e in data" :key="e.id">
              <TableRow>
                <TableCell>
                  <Button
                    v-if="e.before || e.after"
                    variant="ghost"
                    size="icon-xs"
                    :aria-expanded="!!open[e.id]"
                    :aria-label="`Before and after for entry ${e.id}`"
                    @click="open[e.id] = !open[e.id]"
                  >
                    {{ open[e.id] ? '−' : '+' }}
                  </Button>
                </TableCell>
                <TableCell class="whitespace-nowrap">{{ fmtDate(e.ts) }}</TableCell>
                <TableCell>{{ e.actor }}</TableCell>
                <TableCell class="font-mono text-xs">{{ e.action }}</TableCell>
                <TableCell class="max-w-64 truncate" :title="e.target">{{ e.target }}</TableCell>
                <TableCell class="font-mono text-xs">{{ e.source_ip || '-' }}</TableCell>
              </TableRow>
              <TableRow v-if="open[e.id]" class="bg-muted/30 hover:bg-muted/30">
                <TableCell colspan="6" class="whitespace-normal">
                  <div class="grid gap-3 md:grid-cols-2">
                    <div>
                      <p class="text-xs font-medium">Before</p>
                      <pre class="overflow-auto font-mono text-xs">{{ e.before || '-' }}</pre>
                    </div>
                    <div>
                      <p class="text-xs font-medium">After</p>
                      <pre class="overflow-auto font-mono text-xs">{{ e.after || '-' }}</pre>
                    </div>
                  </div>
                </TableCell>
              </TableRow>
            </template>
          </TableBody>
        </Table>
      </LoadState>
    </CardContent>
  </Card>
  <div class="flex justify-end gap-2">
    <Button variant="outline" size="sm" :disabled="offset === 0" @click="offset = Math.max(0, offset - PAGE)">
      Newer
    </Button>
    <Button variant="outline" size="sm" :disabled="(data?.length || 0) < PAGE" @click="offset += PAGE">Older</Button>
  </div>
</template>
