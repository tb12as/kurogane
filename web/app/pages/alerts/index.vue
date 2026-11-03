<script setup lang="ts">
useHead({ title: 'Alerts · ServerKeeper' })
const tab = useTab('events')
</script>

<template>
  <h1 class="text-2xl font-semibold">Alerts</h1>
  <Tabs v-model="tab">
    <TabsList>
      <TabsTrigger value="events">Events</TabsTrigger>
      <TabsTrigger value="rules">Rules</TabsTrigger>
      <TabsTrigger value="silences">Silences</TabsTrigger>
      <TabsTrigger value="channels">Channels</TabsTrigger>
    </TabsList>
    <TabsContent value="events" class="space-y-3"><AlertsEvents /></TabsContent>
    <TabsContent value="rules" class="space-y-3"><AlertsRules /></TabsContent>
    <TabsContent value="silences" class="space-y-3"><AlertsSilences /></TabsContent>
    <TabsContent value="channels" class="space-y-3"><AlertsChannels /></TabsContent>
  </Tabs>
</template>
