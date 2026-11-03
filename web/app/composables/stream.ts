import type { Snapshot } from '~/types/models'

let es: EventSource | null = null

// live state fed by GET /api/v1/stream; pages watch the counters to refetch
export const useLive = () => ({
  snap: useState<Snapshot | null>('live.snap', () => null),
  connected: useState('live.connected', () => false),
  tick: useState('live.tick', () => ({ alert: 0, ssh: 0, harden: 0 })),
  last: useState<Record<string, any>>('live.last', () => ({})), // latest payload per event type
})

export function startStream() {
  if (es) return
  const l = useLive()
  es = new EventSource('/api/v1/stream')
  es.onopen = () => (l.connected.value = true)
  es.onerror = () => (l.connected.value = false) // EventSource reconnects on its own
  es.addEventListener('metrics', e => {
    try {
      l.snap.value = JSON.parse((e as MessageEvent).data)
    } catch {
      /* ignore malformed frame */
    }
  })
  for (const k of ['alert', 'ssh', 'harden'] as const) {
    es.addEventListener(k, e => {
      try {
        l.last.value[k] = JSON.parse((e as MessageEvent).data)
      } catch {
        /* payload is optional; the tick still triggers a refetch */
      }
      l.tick.value[k]++
    })
  }
}

export function stopStream() {
  es?.close()
  es = null
  useLive().connected.value = false
}

export function metric(s: Snapshot | null | undefined, name: string, labels?: Record<string, string>) {
  const x = s?.samples?.find(
    v => v.metric === name && (!labels || Object.entries(labels).every(([k, w]) => v.labels?.[k] === w)),
  )
  return x?.value
}
