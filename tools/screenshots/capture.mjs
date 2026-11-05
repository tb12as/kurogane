// Captures the README screenshots (dark theme, Default density) from a running Kurogane agent.
//
// Point it at a demo agent, never a production one: the images are published in the README.
// The page for one server shows its processes and sessions, so those panels are left out.
//
//   KRGN_URL=http://127.0.0.1:9443 KRGN_USER=admin KRGN_PASSWORD=... KRGN_TOTP_SECRET=... \
//     node tools/screenshots/capture.mjs
//
// KRGN_TOTP_SECRET is the base32 secret printed by `kurogane init` (or pass a current code as KRGN_TOTP).
// The "alert-rule-builder" shot opens the rule with id data-disk-full, so create it first, for example
// `disk.used_pct{mount="/data"} > 85` for 5 minutes. Needs Playwright with Chromium (npm i -g playwright).
// Pass shot names (overview metrics ...) to retake only those; KRGN_OUT changes the output folder.
// Compress the PNGs afterwards:
//   pngquant --quality 70-95 --skip-if-larger --strip --ext .png --force docs/screenshots/*.png
import { createHmac } from 'node:crypto'
import { mkdirSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const { chromium } = createRequire(import.meta.url)('playwright')
const env = name => process.env[name] || ''
const BASE = (env('KRGN_URL') || 'http://127.0.0.1:9443').replace(/\/$/, '')
const OUT = env('KRGN_OUT') || join(dirname(fileURLToPath(import.meta.url)), '../../docs/screenshots')
const WIDTH = 1440

function totp(secret) {
  const abc = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  let bits = ''
  for (const c of secret.toUpperCase().replace(/[=\s]/g, '')) bits += abc.indexOf(c).toString(2).padStart(5, '0')
  const key = Buffer.from(bits.match(/.{8}/g).map(b => parseInt(b, 2)))
  const ctr = Buffer.alloc(8)
  ctr.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)))
  const h = createHmac('sha1', key).update(ctr).digest()
  const o = h[19] & 15
  return String((h.readUInt32BE(o) & 0x7fffffff) % 1e6).padStart(6, '0')
}

// fit sizes the viewport to the page content (within bounds) so short pages have no empty band
async function fit(p, min = 640, max = 1000) {
  await p.setViewportSize({ width: WIDTH, height: 400 })
  const h = await p.evaluate(() => document.getElementById('main').scrollHeight)
  await p.setViewportSize({ width: WIDTH, height: Math.min(max, Math.max(min, Math.ceil(h))) })
  await p.waitForTimeout(600) // charts and tables settle after the resize
}

async function open(p, path, ready) {
  await p.setViewportSize({ width: WIDTH, height: 900 })
  await p.goto(BASE + path)
  await p.getByText(ready, { exact: false }).first().waitFor()
  await p.waitForTimeout(1500)
}

// union of element boxes plus padding, in page coordinates
async function clipOf(locators, pad = 16) {
  const boxes = []
  for (const l of locators) {
    const b = await l.boundingBox() // viewport coordinates; the clip below is in page coordinates
    const sy = await l.page().evaluate(() => window.scrollY)
    boxes.push({ ...b, y: b.y + sy })
  }
  const x = Math.min(...boxes.map(b => b.x)) - pad
  const y = Math.min(...boxes.map(b => b.y)) - pad
  const r = Math.max(...boxes.map(b => b.x + b.width)) + pad
  const btm = Math.max(...boxes.map(b => b.y + b.height)) + pad
  return { x: Math.max(0, x), y: Math.max(0, y), width: r - Math.max(0, x), height: btm - Math.max(0, y) }
}

const shots = {
  async overview(p) {
    await open(p, '/', 'Active alerts')
    await fit(p, 600, 900)
  },
  async metrics(p) {
    await open(p, '/servers/local', 'Network per interface')
    const card = p.locator('[data-slot=card]', { hasText: 'Network per interface' }).first()
    const btn = card.getByRole('button', { name: /full width/ })
    if ((await btn.getAttribute('aria-pressed')) !== 'true') await btn.click()
    await p.mouse.move(0, 0) // no hover state on the chart buttons
    await p.waitForTimeout(1200)
    // the viewport ends just below the widened chart, so the sidebar keeps its footer at the bottom
    await p.evaluate(() => window.scrollTo(0, 0))
    const b = await card.boundingBox()
    await p.setViewportSize({ width: WIDTH, height: Math.ceil(b.y + b.height + 16) })
    await p.waitForTimeout(800)
  },
  async 'alert-rule-builder'(p) {
    await open(p, '/alerts?tab=rules', 'Data disk almost full')
    const row = p.locator('tr', { hasText: 'Data disk almost full' }).first()
    await row.getByRole('button', { name: 'Edit' }).click()
    await p.getByRole('dialog').getByText('Now:').first().waitFor()
    await p.evaluate(() => document.activeElement?.blur()) // no focus ring or selected text in the name field
    await p.waitForTimeout(800)
  },
  async hardening(p) {
    await open(p, '/hardening', '/ 100')
    await fit(p, 640, 1000)
  },
  async sites(p) {
    await open(p, '/sites', 'shop.example.org')
    await fit(p, 600, 1000)
  },
  async 'redis-certs'(p) {
    await open(p, '/servers/local', 'Redis ·')
    const redis = p.locator('[data-slot=card]', { hasText: 'Redis ·' })
    const certs = p.locator('[data-slot=card]', { hasText: 'TLS certificates' }).first()
    await certs.locator('table').waitFor()
    await certs.scrollIntoViewIfNeeded()
    await p.waitForTimeout(500)
    return { fullPage: true, clip: await clipOf([...(await redis.all()), certs], 16) }
  },
  async 'ssh-keys'(p) {
    await open(p, '/ssh', 'Fingerprint')
    await fit(p, 520, 900)
  },
}

const b = await chromium.launch()
const ctx = await b.newContext({ viewport: { width: WIDTH, height: 900 }, deviceScaleFactor: 2, colorScheme: 'dark' })
await ctx.addInitScript(() => {
  localStorage.setItem('vueuse-color-scheme', 'dark')
  localStorage.setItem('krgn.density', 'default')
})
const p = await ctx.newPage()
p.on('pageerror', e => console.error('page error:', e.message))

await p.goto(BASE + '/login')
await p.fill('#u', env('KRGN_USER') || 'admin')
await p.fill('#p', env('KRGN_PASSWORD'))
await p.fill('#t', env('KRGN_TOTP') || totp(env('KRGN_TOTP_SECRET')))
await p.click('button[type=submit]')
await p.waitForURL(u => !u.pathname.startsWith('/login'), { timeout: 15000 })

mkdirSync(OUT, { recursive: true })
const only = process.argv.slice(2)
for (const [name, take] of Object.entries(shots)) {
  if (only.length && !only.includes(name)) continue
  const o = (await take(p)) || {}
  const path = join(OUT, name + '.png')
  await p.screenshot({ path, fullPage: !!o.fullPage, clip: o.clip, animations: 'disabled', caret: 'hide' })
  console.log('wrote', path)
}
await b.close()
