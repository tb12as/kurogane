export interface Me {
  actor: string
  role?: string
  scopes: string[]
  csrf?: string
  oidc?: boolean
}

export const useMe = () => useState<Me | null>('me', () => null)

// null = not probed yet; true on the central server (fleet view), from GET /health
export const useFleet = () => useState<boolean | null>('fleet', () => null)

export function can(scope: string) {
  const s = useMe().value?.scopes || []
  return s.includes('admin') || s.includes(scope)
}

export async function loadMe() {
  const me = await api.get('/auth/me')
  useMe().value = me as Me
  useState('csrf').value = me.csrf
  return me
}

export async function probeFleet() {
  const f = useFleet()
  if (f.value !== null) return f.value
  try {
    // shortcut: the spec's /health schema lacks oidc/central (handler returns them); drop the cast once it is updated
    f.value = ((await api.get('/health')) as { central?: boolean }).central === true
  } catch {
    f.value = false
  }
  return f.value
}

export async function logout() {
  await run(() => api.post('/auth/logout'))
  stopStream()
  useMe().value = null
  await navigateTo('/login')
}
