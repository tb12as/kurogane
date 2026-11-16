<script setup lang="ts">
import { ditherMask } from '~/lib/dither'

// drawn at half resolution and shown at exactly 2x, so every dot is a crisp 2x2 block at any size
const el = ref<HTMLCanvasElement>()
let ro: ResizeObserver | undefined

function draw(c: HTMLCanvasElement) {
  const w = Math.ceil(c.clientWidth / 2)
  const h = Math.ceil(c.clientHeight / 2)
  if (!w || !h || (c.width === w && c.height === h)) return

  c.width = w
  c.height = h
  const ctx = c.getContext('2d')
  if (!ctx) return

  const m = ditherMask(w, h)
  const img = ctx.createImageData(w, h)
  for (let i = 0; i < m.length; i++) {
    if (!m[i]) continue
    const p = i * 4
    img.data[p] = 0xf6
    img.data[p + 1] = 0x5f
    img.data[p + 2] = 0x0a
    img.data[p + 3] = 255
  }
  ctx.putImageData(img, 0, 0)
}

onMounted(() => {
  const c = el.value
  if (!c) return
  ro = new ResizeObserver(() => draw(c))
  ro.observe(c)
})
onBeforeUnmount(() => ro?.disconnect())
</script>

<template>
  <canvas ref="el" aria-hidden="true" class="dither-canvas" />
</template>
