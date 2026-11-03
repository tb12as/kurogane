<script setup lang="ts">
// button + confirmation dialog for simple destructive actions without a diff
const props = withDefaults(
  defineProps<{
    title: string
    description?: string
    action: () => Promise<unknown>
    confirm?: string
    variant?: 'default' | 'destructive' | 'outline' | 'ghost' | 'secondary'
    size?: 'default' | 'sm' | 'xs'
    disabled?: boolean
  }>(),
  { confirm: 'Confirm', variant: 'outline', size: 'sm' },
)
const open = ref(false)
const busy = ref(false)
async function go() {
  busy.value = true
  try {
    await props.action()
    open.value = false
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <AlertDialog v-model:open="open">
    <AlertDialogTrigger as-child>
      <Button :variant="variant" :size="size" :disabled="disabled"><slot /></Button>
    </AlertDialogTrigger>
    <AlertDialogContent>
      <AlertDialogHeader>
        <AlertDialogTitle>{{ title }}</AlertDialogTitle>
        <AlertDialogDescription v-if="description">{{ description }}</AlertDialogDescription>
      </AlertDialogHeader>
      <AlertDialogFooter>
        <AlertDialogCancel :disabled="busy">Cancel</AlertDialogCancel>
        <Button variant="destructive" :disabled="busy" @click="go">{{ busy ? 'Working…' : confirm }}</Button>
      </AlertDialogFooter>
    </AlertDialogContent>
  </AlertDialog>
</template>
