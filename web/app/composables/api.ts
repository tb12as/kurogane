import createClient from 'openapi-fetch'
import { toast } from 'vue-sonner'
import type { paths } from '~/types/api'

// response type from the generated spec when the path is known, otherwise any (loose until the spec is complete)
type JSONOf<T> = T extends { responses: { 200: { content: { 'application/json': infer R } } } } ? R : any
type Res<P, M extends string> = P extends keyof paths ? (M extends keyof paths[P] ? JSONOf<paths[P][M]> : any) : any

export interface ReqOpts {
  query?: Record<string, string | number | boolean | undefined | null>
  path?: Record<string, string | number>
  body?: unknown
}

export class ApiError extends Error {
  constructor(
    msg: string,
    public status: number,
  ) {
    super(msg)
  }
}

export function csrfToken(): string {
  const m = document.cookie.match(/(?:^|; )krgn_csrf=([^;]*)/)
  return m ? decodeURIComponent(m[1]!) : useState<string>('csrf').value || ''
}

const client = createClient<paths>({ baseUrl: '/api/v1', credentials: 'same-origin' })

client.use({
  onRequest({ request }) {
    if (request.method !== 'GET' && request.method !== 'HEAD') request.headers.set('X-CSRF-Token', csrfToken())
    return request
  },
  onResponse({ response, request }) {
    const r = useRoute()
    if (response.status === 401 && r.path !== '/login' && !/\/auth\/(login|me)$/.test(new URL(request.url).pathname)) {
      navigateTo({ path: '/login', query: { next: r.fullPath } })
    }
    return response
  },
})

function clean(q?: ReqOpts['query']) {
  if (!q) return undefined
  const o: Record<string, string | number | boolean> = {}
  for (const [k, v] of Object.entries(q)) if (v !== undefined && v !== null && v !== '') o[k] = v
  return o
}

async function call<T>(method: string, path: string, o: ReqOpts = {}): Promise<T> {
  const fn = (client as any)[method] as (p: string, i: unknown) => Promise<any>
  const init: Record<string, unknown> = { params: { query: clean(o.query), path: o.path } }
  if (o.body !== undefined) init.body = o.body
  const { data, error, response } = await fn(path, init)
  if (!response.ok) {
    const msg = (error && typeof error === 'object' && error.error) || (typeof error === 'string' && error)
    throw new ApiError(msg || `${response.status} ${response.statusText}`, response.status)
  }
  return data as T
}

export const api = {
  get: <P extends string>(p: P, o?: ReqOpts) => call<Res<P, 'get'>>('GET', p, o),
  post: <P extends string>(p: P, body?: unknown, o?: ReqOpts) => call<Res<P, 'post'>>('POST', p, { ...o, body }),
  put: <P extends string>(p: P, body?: unknown, o?: ReqOpts) => call<Res<P, 'put'>>('PUT', p, { ...o, body }),
  patch: <P extends string>(p: P, body?: unknown, o?: ReqOpts) => call<Res<P, 'patch'>>('PATCH', p, { ...o, body }),
  del: <P extends string>(p: P, o?: ReqOpts) => call<Res<P, 'delete'>>('DELETE', p, o),
}

// absolute URL for downloads (report, CSV export) that the browser fetches with the session cookie
export function apiUrl(path: string, q?: ReqOpts['query']) {
  const s = new URLSearchParams(clean(q) as Record<string, string>).toString()
  return '/api/v1' + path + (s ? '?' + s : '')
}

// run a mutation; toasts the API's error message (it states cause + next step)
export async function run<T>(fn: () => Promise<T>, ok?: string): Promise<T | undefined> {
  try {
    const r = await fn()
    if (ok) toast.success(ok)
    return r
  } catch (e) {
    toast.error(e instanceof Error ? e.message : String(e))
    return undefined
  }
}

export function errMsg(e: unknown) {
  return e instanceof Error ? e.message : e ? String(e) : ''
}

// list endpoints may return a bare array or {items|<key>: [...]}; accept both until the spec settles
export function list<T = any>(r: unknown, key?: string): T[] {
  if (Array.isArray(r)) return r as T[]
  if (r && typeof r === 'object') {
    const o = r as Record<string, unknown>
    const v = (key && o[key]) || o.items || o.data
    if (Array.isArray(v)) return v as T[]
  }
  return []
}
