<script setup lang="ts">
definePageMeta({ layout: false })
useHead({ title: 'Sign in · Kurogane' })

const route = useRoute()
const f = reactive({ username: '', password: '', totp: '' })
const err = ref('')
const busy = ref(false)
const oidc = ref(false)

onMounted(async () => {
  // public endpoint: /auth/me needs a session
  const h = (await api.get('/health').catch(() => null)) as { oidc?: boolean } | null
  oidc.value = h?.oidc === true
})

async function submit() {
  err.value = ''
  busy.value = true
  try {
    const r = await api.post('/auth/login', { ...f })
    useState('csrf').value = r?.csrf
    await loadMe()
    await probeFleet()
    const next = typeof route.query.next === 'string' && route.query.next.startsWith('/') ? route.query.next : '/'
    await navigateTo(next)
  } catch (e) {
    err.value = errMsg(e)
    f.totp = ''
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <main class="flex min-h-dvh items-center justify-center p-4">
    <Card class="w-full max-w-sm">
      <CardHeader>
        <CardTitle class="flex items-center gap-2 text-xl">
          <Logo class="size-7" />
          Kurogane
        </CardTitle>
        <CardDescription>Sign in with your password and authenticator code.</CardDescription>
      </CardHeader>
      <CardContent>
        <form class="space-y-4" @submit.prevent="submit">
          <div class="space-y-1.5">
            <Label for="u">Username</Label>
            <Input id="u" v-model="f.username" autocomplete="username" required autofocus />
          </div>
          <div class="space-y-1.5">
            <Label for="p">Password</Label>
            <Input id="p" v-model="f.password" type="password" autocomplete="current-password" required />
          </div>
          <div class="space-y-1.5">
            <Label for="t">Authenticator code</Label>
            <Input
              id="t"
              v-model="f.totp"
              inputmode="numeric"
              autocomplete="one-time-code"
              pattern="[0-9]{6}"
              maxlength="6"
              placeholder="123456"
              required
            />
          </div>
          <p v-if="err" role="alert" class="text-sm text-destructive">{{ err }}</p>
          <Button type="submit" class="w-full" :disabled="busy">{{ busy ? 'Signing in…' : 'Sign in' }}</Button>
        </form>
        <template v-if="oidc">
          <Separator class="my-4" />
          <Button as="a" href="/api/v1/auth/oidc/login" variant="outline" class="w-full">Sign in with SSO</Button>
        </template>
      </CardContent>
    </Card>
  </main>
</template>
