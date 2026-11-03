<script setup lang="ts">
// shadcn Select with a flat option list; reka-ui reserves "" so "all" style filters use a sentinel value
const props = defineProps<{
  options: (string | { value: string; label: string })[]
  placeholder?: string
  id?: string
  label?: string
}>()
const model = defineModel<string>()
const opts = computed(() => props.options.map(o => (typeof o === 'string' ? { value: o, label: o } : o)))
</script>

<template>
  <Select v-model="model">
    <SelectTrigger :id="id" :aria-label="label" class="w-full min-w-32">
      <SelectValue :placeholder="placeholder" />
    </SelectTrigger>
    <SelectContent>
      <SelectItem v-for="o in opts" :key="o.value" :value="o.value">{{ o.label }}</SelectItem>
    </SelectContent>
  </Select>
</template>
