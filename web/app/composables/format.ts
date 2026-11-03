// go zero time (0001-01-01) and empty strings mean "never"
export function when(s?: string | null) {
  if (!s) return null
  const d = new Date(s)
  return isNaN(d.getTime()) || d.getFullYear() < 1971 ? null : d
}

export function fmtDate(s?: string | null) {
  const d = when(s)
  return d ? d.toLocaleString() : '—'
}

export function ago(s?: string | null) {
  const d = when(s)
  if (!d) return '—'
  const sec = Math.round((Date.now() - d.getTime()) / 1000)
  const a = Math.abs(sec)
  let t: string
  if (a < 60) t = `${a}s`
  else if (a < 3600) t = `${Math.round(a / 60)}m`
  else if (a < 86400) t = `${Math.round(a / 3600)}h`
  else t = `${Math.round(a / 86400)}d`
  return sec >= 0 ? `${t} ago` : `in ${t}`
}

export function bytes(n?: number | null, suffix = '') {
  if (n === undefined || n === null || isNaN(n)) return '—'
  const u = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
  let i = 0
  while (Math.abs(n) >= 1024 && i < u.length - 1) {
    n /= 1024
    i++
  }
  return `${n.toFixed(i && n < 10 ? 1 : 0)} ${u[i]}${suffix}`
}

export function pct(n?: number | null) {
  return n === undefined || n === null ? '—' : `${n.toFixed(1)}%`
}

export function num(n?: number | null, d = 0) {
  return n === undefined || n === null ? '—' : n.toLocaleString(undefined, { maximumFractionDigits: d })
}

export function uptime(s?: number) {
  if (!s) return '—'
  const d = Math.floor(s / 86400),
    h = Math.floor((s % 86400) / 3600),
    m = Math.floor((s % 3600) / 60)
  return d ? `${d}d ${h}h` : `${h}h ${m}m`
}

// Go time.Duration marshals as nanoseconds
export function dur(v?: number | string | null) {
  if (v === undefined || v === null || v === '') return '—'
  if (typeof v === 'string') return v
  let s = Math.round(v / 1e9)
  if (s % 3600 === 0 && s) return `${s / 3600}h`
  if (s % 60 === 0 && s) return `${s / 60}m`
  return `${s}s`
}

// "90s", "5m", "1h30m", "2d" -> ms
export function parseDur(s: string): number | null {
  const re = /(\d+(?:\.\d+)?)(ms|s|m|h|d|w)/g
  const mul: Record<string, number> = { ms: 1, s: 1e3, m: 6e4, h: 36e5, d: 864e5, w: 6048e5 }
  let t = 0,
    seen = ''
  for (const m of s.trim().matchAll(re)) {
    t += parseFloat(m[1]!) * mul[m[2]!]!
    seen += m[0]
  }
  return seen && seen === s.trim() ? t : null
}

export function download(name: string, text: string) {
  const a = document.createElement('a')
  a.href = URL.createObjectURL(new Blob([text], { type: 'text/plain' }))
  a.download = name
  a.click()
  URL.revokeObjectURL(a.href)
}
