import { useDark } from '@vueuse/core'

// applies the saved theme on every page, including the sign-in page, which has no layout
export default defineNuxtPlugin(() => {
  useDark()
})
