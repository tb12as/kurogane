// applies the saved density before the app mounts, so the page does not jump on load
export default defineNuxtPlugin(() => {
  const density = useDensity()
  applyDensity(density.value)
  watch(density, applyDensity)
})
