<script setup lang="ts">
// deep link used by Slack/Discord "Silence 1h" buttons: /alerts/silence?rule=X&for=1h
const route = useRoute()
await navigateTo({ path: '/alerts', query: { ...route.query, tab: 'silences' } }, { replace: true })
</script>

<template><p class="text-sm text-muted-foreground">Opening silences…</p></template>
