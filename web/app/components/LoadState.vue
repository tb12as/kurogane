<script setup lang="ts">
// loading / error / empty placeholder for an async block; renders the slot when there is data
defineProps<{ pending?: boolean; error?: unknown; empty?: boolean; emptyText?: string }>()
</script>

<template>
  <div v-if="pending" class="space-y-2 py-2" aria-busy="true">
    <Skeleton class="h-5 w-full" />
    <Skeleton class="h-5 w-4/5" />
    <span class="sr-only">Loading</span>
  </div>
  <Alert v-else-if="error" variant="destructive">
    <AlertTitle>Could not load</AlertTitle>
    <AlertDescription>{{ errMsg(error) }}</AlertDescription>
  </Alert>
  <p v-else-if="empty" class="py-6 text-center text-sm text-muted-foreground">{{ emptyText || 'Nothing here yet.' }}</p>
  <slot v-else />
</template>
