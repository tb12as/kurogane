<script setup lang="ts">
useHead({ title: 'Sites · Kurogane' })
const fleet = useFleet()
const tab = useTab('sites')
</script>

<template>
  <h1 class="text-2xl font-semibold">Sites</h1>
  <p class="max-w-3xl text-sm text-muted-foreground">
    nginx and Apache sites. Switching a site on or off only links, unlinks or renames its file; the change is checked
    with the server's own config test and undone automatically if the reload fails or another site stops answering.
  </p>
  <SitesFleet v-if="fleet" />
  <Tabs v-else v-model="tab">
    <TabsList>
      <TabsTrigger value="sites">Sites</TabsTrigger>
      <TabsTrigger value="changes">Change history</TabsTrigger>
    </TabsList>
    <TabsContent value="sites"><SitesLocal /></TabsContent>
    <TabsContent value="changes"><SitesChanges /></TabsContent>
  </Tabs>
</template>
