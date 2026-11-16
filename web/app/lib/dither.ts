// 8x8 Bayer threshold matrix (0..63)
const B = [
  0, 32, 8, 40, 2, 34, 10, 42, 48, 16, 56, 24, 50, 18, 58, 26, 12, 44, 4, 36, 14, 46, 6, 38, 60, 28, 52, 20, 62, 30,
  54, 22, 3, 35, 11, 43, 1, 33, 9, 41, 51, 19, 59, 27, 49, 17, 57, 25, 15, 47, 7, 39, 13, 45, 5, 37, 63, 31, 55, 23,
  61, 29, 53, 21,
]

// fade reaches zero at this normalized distance from its corner; the centre is at hypot(0.5, 0.5) = 0.707
const REACH = 0.7

// ordered dither of two fades, from the top-left and bottom-right corners, that die out before the middle.
// returns 1 per cell that is on, row-major, w x h
export function ditherMask(w: number, h: number, pow = 1.8): Uint8Array {
  const m = new Uint8Array(w * h)
  const fade = (dx: number, dy: number) => Math.max(0, 1 - Math.hypot(dx / w, dy / h) / REACH) ** pow
  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      const v = Math.max(fade(x, y), fade(w - 1 - x, h - 1 - y))
      if (v * 64 > B[(y % 8) * 8 + (x % 8)]!) m[y * w + x] = 1
    }
  }
  return m
}
