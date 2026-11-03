export default defineNuxtRouteMiddleware(async to => {
  if (to.path === '/login') return
  const me = useMe()
  if (me.value) return
  try {
    await loadMe()
  } catch {
    return navigateTo({ path: '/login', query: to.fullPath === '/' ? {} : { next: to.fullPath } })
  }
  await probeFleet()
})
