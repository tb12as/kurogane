// run: pnpm test
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { ditherMask } from '../app/lib/dither.ts'

const share = (m: Uint8Array, w: number, x0: number, y0: number, n: number) => {
  let on = 0
  for (let y = y0; y < y0 + n; y++) for (let x = x0; x < x0 + n; x++) on += m[y * w + x]!
  return on / (n * n)
}

test('ditherMask is dense in the top-left and bottom-right corners and empty in the middle', () => {
  const w = 64
  const h = 40
  const m = ditherMask(w, h)
  assert.equal(m.length, w * h)
  assert.ok(share(m, w, 0, 0, 8) > 0.4)
  assert.ok(share(m, w, w - 8, h - 8, 8) > 0.4)
  assert.equal(m[(h / 2) * w + w / 2], 0)
  assert.ok(share(m, w, w / 2 - 4, h / 2 - 4, 8) < 0.1)
  // the other two corners are past the reach of both fades
  assert.equal(share(m, w, w - 8, 0, 8), 0)
  assert.equal(share(m, w, 0, h - 8, 8), 0)
})
