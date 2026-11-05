// Pure helpers for the alert rule builder (no Vue): expression building, wording and value formatting.
// They mirror internal/alert/catalog.go (FormatValue, Describe) so the builder and the server agree.
import { bytes } from './format.ts'
import type { MetricDef, Op, RuleCondition } from '../types/models.ts'

export const OPS: { value: Op; label: string }[] = [
  { value: '>', label: 'above' },
  { value: '>=', label: 'at or above' },
  { value: '<', label: 'below' },
  { value: '<=', label: 'at or below' },
  { value: '==', label: 'equal to' },
  { value: '!=', label: 'not equal to' },
]
const OP_WORD = Object.fromEntries(OPS.map(o => [o.value, o.label])) as Record<Op, string>

// "for" choices in nanoseconds (Go time.Duration)
const MIN = 60e9
export const FOR_OPTIONS = [
  { ns: 0, label: 'Immediately' },
  { ns: MIN, label: '1 minute' },
  { ns: 2 * MIN, label: '2 minutes' },
  { ns: 5 * MIN, label: '5 minutes' },
  { ns: 10 * MIN, label: '10 minutes' },
  { ns: 15 * MIN, label: '15 minutes' },
  { ns: 30 * MIN, label: '30 minutes' },
  { ns: 60 * MIN, label: '1 hour' },
]

export function numText(v: number): string {
  // no exponent notation in expressions or labels
  return Number.isInteger(v) ? String(v) : String(Number(v.toFixed(6)))
}

export function formatValue(d: Pick<MetricDef, 'unit'> | undefined, v: number): string {
  const n = numText(v)
  switch (d?.unit) {
    case 'pct':
      return `${n} %`
    case 'bytes':
      return bytes(v)
    case 'bytes_ps':
      return bytes(v, '/s')
    case 'per_s':
      return `${n}/s`
    case 'ms':
      return `${n} ms`
    case 's':
      return `${n} s`
    case 'h':
      return `${n} h`
    case 'days':
      return v === 1 ? '1 day' : `${n} days`
    case 'ratio':
      return `${n}×`
  }
  return n
}

export const UNIT_SUFFIX: Record<string, string> = {
  pct: '%',
  bytes: 'bytes',
  bytes_ps: 'bytes/s',
  per_s: '/s',
  ms: 'ms',
  s: 'seconds',
  h: 'hours',
  days: 'days',
  ratio: '×',
}

// boolState names the state a bool comparison selects ("up", "down"), or "" when it is not a plain is-test
export function boolState(d: MetricDef, op: Op, v: number): string {
  const one = d.states?.['1'] ?? 'up'
  const zero = d.states?.['0'] ?? 'down'
  if ((op === '==' && v === 1) || (op === '!=' && v === 0) || (op === '>' && v === 0) || (op === '>=' && v === 1)) return one
  if ((op === '==' && v === 0) || (op === '!=' && v === 1) || (op === '<' && v === 1) || (op === '<=' && v === 0)) return zero
  return ''
}

export function labelText(labels?: Record<string, string>): string {
  const ks = Object.keys(labels || {}).sort()
  return ks.length ? ` (${ks.map(k => `${k} ${labels![k]}`).join(', ')})` : ''
}

// describe renders a condition in words, like alert.Describe: "Disk space used (mount /) above 85 %"
export function describe(c: RuleCondition, d?: MetricDef): string {
  const title = (d?.title ?? c.metric) + labelText(c.labels)
  if (d?.unit === 'bool') {
    const s = boolState(d, c.op, c.value)
    if (s) return `${title} is ${s}`
  }
  return `${title} ${OP_WORD[c.op]} ${formatValue(d, c.value)}`
}

// condExpr renders one condition in the rule expression syntax (internal/alert/expr.go)
export function condExpr(c: RuleCondition): string {
  const ks = Object.keys(c.labels || {})
    .filter(k => c.labels![k] !== '')
    .sort()
  const sel = ks.length ? `{${ks.map(k => `${k}="${c.labels![k]!.replace(/["\\\\]/g, '')}"`).join(',')}}` : ''
  return `${c.metric}${sel} ${c.op} ${numText(c.value)}`
}

export function buildExpr(join: 'and' | 'or', items: RuleCondition[]): string {
  return items.map(condExpr).join(` ${join} `)
}

// slug turns a rule name into an id: "Root disk almost full!" -> "root_disk_almost_full"
export function slug(name: string): string {
  return name
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .slice(0, 48)
}

export function forLabel(ns: number): string {
  const o = FOR_OPTIONS.find(x => x.ns === ns)
  if (o) return o.label
  const s = Math.round(ns / 1e9)
  if (s % 3600 === 0) return `${s / 3600} hours`
  if (s % 60 === 0) return `${s / 60} minutes`
  return `${s} seconds`
}

// matches reports whether a live series satisfies a condition (label filter and comparison)
export function matches(c: RuleCondition, s: { labels?: Record<string, string>; value: number }): boolean {
  for (const [k, v] of Object.entries(c.labels || {})) if (v !== '' && s.labels?.[k] !== v) return false
  const x = s.value
  switch (c.op) {
    case '>':
      return x > c.value
    case '>=':
      return x >= c.value
    case '<':
      return x < c.value
    case '<=':
      return x <= c.value
    case '==':
      return x === c.value
  }
  return x !== c.value
}
