<script setup lang="ts">
import { toast } from 'vue-sonner'
import type { Preview } from '~/types/models'

// every risky action (PRD §11.5): fetch a dry-run, show diff + plain-language impact, then apply on confirm
const props = withDefaults(
  defineProps<{
    title: string
    preview: () => Promise<Preview | undefined>
    apply: () => Promise<unknown>
    impact?: string | string[] // client-side impact shown when the dry-run has none
    confirm?: string
    wide?: boolean
  }>(),
  { confirm: 'Apply' },
)
const emit = defineEmits<{ done: [unknown] }>()
const open = defineModel<boolean>('open', { default: false })
const p = ref<Preview>()
const err = ref('')
const loading = ref(false)
const busy = ref(false)

watch(open, async o => {
  if (!o) return
  p.value = undefined
  err.value = ''
  loading.value = true
  try {
    p.value = (await props.preview()) || {}
  } catch (e) {
    err.value = errMsg(e)
    toast.error(err.value)
  } finally {
    loading.value = false
  }
})

const impacts = computed(() => {
  const v = p.value?.impact || props.impact
  return Array.isArray(v) ? v : v ? [v] : []
})

async function go() {
  busy.value = true
  try {
    const r = await props.apply()
    open.value = false
    emit('done', r)
  } catch (e) {
    toast.error(errMsg(e))
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <Dialog v-model:open="open">
    <DialogScrollContent :class="wide ? 'sm:max-w-3xl' : 'sm:max-w-2xl'">
      <DialogHeader>
        <DialogTitle>{{ title }}</DialogTitle>
        <DialogDescription>
          Dry run: nothing has changed yet. Review the diff and impact, then confirm.
        </DialogDescription>
      </DialogHeader>
      <slot />
      <LoadState :pending="loading" :error="err">
        <section v-if="impacts.length" aria-label="Impact" class="space-y-1">
          <h3 class="text-sm font-medium">What this changes</h3>
          <ul class="list-disc space-y-1 pl-5 text-sm">
            <li v-for="(x, i) in impacts" :key="i">{{ x }}</li>
          </ul>
        </section>
        <Alert v-for="(w, i) in p?.warnings || []" :key="'w' + i" class="border-warn/50">
          <AlertTitle class="text-warn">Warning</AlertTitle>
          <AlertDescription>{{ w }}</AlertDescription>
        </Alert>
        <section aria-label="Diff" class="space-y-1">
          <h3 class="text-sm font-medium">Diff</h3>
          <DiffView :diff="p?.diff" />
        </section>
        <slot name="extra" :preview="p" />
      </LoadState>
      <DialogFooter>
        <Button variant="outline" :disabled="busy" @click="open = false">Cancel</Button>
        <Button variant="destructive" :disabled="busy || loading || !!err" @click="go">
          {{ busy ? 'Applying…' : confirm }}
        </Button>
      </DialogFooter>
    </DialogScrollContent>
  </Dialog>
</template>
