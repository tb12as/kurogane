<script setup lang="ts">
useHead({ title: 'SSH · Kurogane' })
const tab = useTab('keys')
const { data: sessions, error: sErr, refresh } = useAsyncData('ssh.sessions', async () =>
  list(await api.get('/ssh/sessions'), 'sessions'),
)
async function kill(pid: number) {
  await run(() => api.del(`/ssh/sessions/${pid}`), `Session ${pid} killed`)
  refresh()
}
</script>

<template>
  <h1 class="text-2xl font-semibold">SSH</h1>
  <Tabs v-model="tab">
    <TabsList class="h-auto flex-wrap justify-start">
      <TabsTrigger value="keys">Keys</TabsTrigger>
      <TabsTrigger value="config">sshd config</TabsTrigger>
      <TabsTrigger value="changes">Change history</TabsTrigger>
      <TabsTrigger value="sessions">Sessions</TabsTrigger>
      <TabsTrigger value="logins">Logins</TabsTrigger>
      <TabsTrigger value="bans">Bans</TabsTrigger>
    </TabsList>
    <TabsContent value="keys" class="space-y-4"><SshKeys /></TabsContent>
    <TabsContent value="config" class="space-y-4"><SshConfig /></TabsContent>
    <TabsContent value="changes"><SshChanges /></TabsContent>
    <TabsContent value="sessions">
      <Card>
        <CardContent>
          <LoadState :error="sErr"><SshSessionsTable :rows="sessions || []" @kill="kill" /></LoadState>
        </CardContent>
      </Card>
    </TabsContent>
    <TabsContent value="logins"><SshLogins /></TabsContent>
    <TabsContent value="bans"><SshBans /></TabsContent>
  </Tabs>
</template>
