<script setup lang="ts">
import type { SiteChange } from '~/types/models'

const live = useLive()
const { data, pending, error, refresh } = useAsyncData('sites.changes', async () =>
  list<SiteChange>(await api.get('/sites/changes')),
)
watch(
  () => live.tick.value.sites,
  () => refresh(),
)
</script>

<template>
  <Card>
    <CardContent>
      <LoadState :pending="pending" :error="error" :empty="!data?.length" empty-text="No site changes recorded.">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>When</TableHead>
              <TableHead>Actor</TableHead>
              <TableHead>Site</TableHead>
              <TableHead>Action</TableHead>
              <TableHead>Detail</TableHead>
              <TableHead>Status</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            <TableRow v-for="c in data" :key="c.id">
              <TableCell class="whitespace-nowrap">{{ fmtDate(c.ts) }}</TableCell>
              <TableCell>{{ c.actor }}</TableCell>
              <TableCell class="font-mono">{{ c.site_name }}</TableCell>
              <TableCell class="capitalize">{{ c.action }}</TableCell>
              <TableCell class="max-w-96 text-xs whitespace-normal break-words">
                <span :class="c.error ? 'text-crit' : 'font-mono'">{{ c.error || c.ops }}</span>
              </TableCell>
              <TableCell><StateBadge :value="c.status" /></TableCell>
            </TableRow>
          </TableBody>
        </Table>
      </LoadState>
    </CardContent>
  </Card>
</template>
