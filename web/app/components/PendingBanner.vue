<script setup lang="ts">
import { useIntervalFn } from '@vueuse/core'
import type { SSHChange } from '~/types/models'

// pending sshd change: prominent countdown until auto-rollback, with Confirm (PRD §6.3)
const live = useLive()
const pending = ref<SSHChange[]>([])
const now = ref(Date.now())
useIntervalFn(() => (now.value = Date.now()), 1000)

async function load() {
  try {
    // change history comes from the database, so this works on hosts without sshd (unlike /ssh/config)
    const p = list<SSHChange>(await api.get('/ssh/changes')).find(c => c.status === 'pending')
    pending.value = p ? [p] : []
  } catch {
    pending.value = [] // central server or no ssh scope: no banner
  }
}
onMounted(load)
// the ssh event carries the SSHChange on pending/confirmed/rolled_back
watch(
  () => live.tick.value.ssh,
  () => {
    const c = live.last.value.ssh as SSHChange | undefined
    if (c?.status) pending.value = c.status === 'pending' ? [c] : []
    else load()
  },
)

const deadline = computed(() => Math.min(...pending.value.map(c => when(c.deadline)?.getTime() || Infinity)))
const left = computed(() => Math.max(0, Math.round((deadline.value - now.value) / 1000)))
watch(left, (l, o) => {
  if (l === 0 && o > 0) setTimeout(load, 3000)
})

const busy = ref(false)
async function confirm() {
  busy.value = true
  await run(() => api.post('/ssh/config/confirm'), 'SSH change confirmed')
  busy.value = false
  load()
}
</script>

<template>
  <div
    v-if="pending.length && isFinite(deadline)"
    role="alert"
    class="flex flex-wrap items-center gap-3 border-b border-warn/50 bg-warn/10 px-4 py-3 text-sm"
  >
    <span class="font-semibold">SSH change pending:</span>
    <span>{{ pending.map(c => `${c.setting} ${c.old_value || '(unset)'} → ${c.new_value}`).join(', ') }}</span>
    <span class="font-mono tabular-nums" aria-live="off">
      rolls back in {{ Math.floor(left / 60) }}:{{ String(left % 60).padStart(2, '0') }}
    </span>
    <span class="text-muted-foreground">Open a new SSH session to verify you can still log in, then confirm.</span>
    <Button size="sm" class="ml-auto" :disabled="busy || left === 0" @click="confirm">Confirm change</Button>
  </div>
</template>
