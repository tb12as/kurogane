// JSON shapes mirrored from internal/db/models.go and internal/collector/types.go.
// shortcut: hand-written until the OpenAPI spec covers every domain; then switch to components['schemas'].

export interface Sample {
  metric: string
  labels?: Record<string, string>
  ts: number
  value: number
}
export interface Proc {
  pid: number
  name: string
  user: string
  cpu_pct: number
  rss: number
  state: string
  cmd: string
}
export interface Mount {
  path: string
  device: string
  fstype: string
  total: number
  used: number
  used_pct: number
}
export interface SystemInfo {
  hostname: string
  os: string
  kernel: string
  arch: string
  uptime_s: number
  reboot_required: boolean
  security_updates: number
  pending_updates: number
  cpus: number
  mem_total: number
}
export interface Snapshot {
  ts: string
  samples: Sample[]
  system: SystemInfo
  top_cpu: Proc[]
  top_mem: Proc[]
  conns: { states: Record<string, number>; top_ips: { ip: string; count: number }[]; syn_cookies: boolean }
  services: { unit: string; active: string; sub: string }[]
  mounts: Mount[]
}
export interface Series {
  metric: string
  labels?: Record<string, string>
  points: [number, number, number][]
}

export interface Server {
  id: string
  name: string
  tags: string[]
  os: string
  kernel: string
  agent_version: string
  last_seen: string
  status: string
  score: number
  grade: string
  // GET /fleet/overview extras; latest keys: cpu, mem, disk (max over mounts)
  connected?: boolean
  active_alerts?: number
  latest?: Record<string, number> | null
}
export interface SSHKey {
  server_id: string
  fingerprint: string
  type: string
  bits: number
  user: string
  label: string
  comment: string
  options: string
  public_key: string
  owner_person: string
  added_at: string
  expires_at: string
  last_used_at: string
  flags?: string[] | null
  file?: string
  line?: number
}
export interface SSHChange {
  id: string
  actor: string
  setting: string
  old_value: string
  new_value: string
  status: 'pending' | 'confirmed' | 'rolled_back' | 'failed'
  ts: string
  deadline: string
}
export interface Fix {
  id: string
  check_id: string
  diff: string
  applied_by: string
  applied_at: string
  reverted_at: string
  status: string
}
export interface Ignore {
  check_id: string
  reason: string
  created_by: string
  created_at: string
  id?: string
}
export interface AlertRule {
  id: string
  name: string
  expr: string
  for: number | string
  severity: string
  channels: string[]
  enabled: boolean
  tags: string[]
  builtin: boolean
}
export interface AlertEvent {
  id: string
  rule_id: string
  server_id: string
  state: string
  severity: string
  summary: string
  started_at: string
  acked_at: string
  acked_by: string
  resolved_at: string
  noise: boolean
}
export interface Silence {
  id: string
  matcher: { server?: string; rule?: string; tag?: string }
  starts_at: string
  ends_at: string
  created_by: string
  reason: string
}
export interface Channel {
  name: string
  type: string
  config?: Record<string, string>
}
export interface User {
  id: string
  username: string
  role: string
  totp_enabled: boolean
  failed_logins: number
  locked_until: string
  created_at: string
}
export interface APIToken {
  id: string
  name: string
  scopes: string[]
  created_by: string
  created_at: string
  expires_at: string
  last_used_at: string
}
export interface AuditEntry {
  id: number
  actor: string
  action: string
  target: string
  before: string
  after: string
  ts: string
  source_ip: string
  server_id: string
}
export interface Person {
  id: string
  name: string
  email: string
  groups: string[]
  keys: { fingerprint: string; public_key: string; login_user: string }[]
}
export interface FleetOp {
  id: string
  server_id: string
  kind: string
  status: string
  result: string
  created_by: string
  created_at: string
  done_at: string
}
// a dry-run answer from any risky endpoint; fields are optional, the UI shows what is present
export interface Preview {
  diff?: string
  impact?: string | string[]
  warnings?: string[]
  [k: string]: unknown
}
export interface Line {
  name: string
  data: [number, number][]
}
