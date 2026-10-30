// Types mirror the Go JSON in server/store, server/analyze and server/triage.

export type ActorClass =
  | "impersonator"
  | "scanner"
  | "verified_bot"
  | "ai_agent"
  | "automation"
  | "crawler"
  | "browser"
  | "unknown"

export type Signal = { code: string; weight: number; detail: string }

export type EnforcementKind = "block" | "challenge" | "rate_limit"
export type RecommendedAction = "none" | "watch" | EnforcementKind

export type Verdict = {
  classification: ActorClass
  risk: number
  confidence: number
  summary: string
  evidence: string[]
  recommended_action: RecommendedAction
  scope: "ip" | "fingerprint"
  ttl_minutes: number
  model: string
}

export type Actor = {
  id: number
  ip: string
  ja4: string
  ua: string
  first_seen: string
  last_seen: string
  requests: number
  rule_score: number
  class: ActorClass
  signals: Signal[]
  verified: string
  triage: Verdict | null
  triage_score: number | null
  triaged_at: string | null
  risk: number
  dismissed_at: string | null
}

export type SensorAction = "allow" | "block" | "challenge" | "challenge_passed" | "rate_limit"

export type RequestEvent = {
  ts: string
  ip: string
  method: string
  host: string
  path: string
  query?: string
  proto: string
  status: number
  duration_ms: number
  bytes_in: number
  bytes_out: number
  ua?: string
  referer?: string
  headers?: string[]
  hints?: Record<string, string>
  ja4?: string
  sni?: string
  action: SensorAction
  decision_id?: number
}

export type DecisionStatus = "pending" | "active" | "rejected" | "revoked" | "expired"

export type Decision = {
  id: number
  actor_id: number | null
  ip: string
  ja4: string
  kind: EnforcementKind
  rpm: number
  ttl_minutes: number
  reason: string
  source: "rules" | "llm" | "manual"
  status: DecisionStatus
  created_at: string
  decided_at: string | null
  expires_at: string | null
  actor?: { ua: string; class: ActorClass; risk: number }
}

export type EgressDest = {
  id: number
  sensor_id: number
  comm: string
  uid: number
  dst_ip: string
  dst_port: number
  first_seen: string
  last_seen: string
  connections: number
  last_pid: number
  flags: ("new_destination" | "uncommon_port")[]
}

export type Sensor = {
  id: number
  name: string
  created_at: string
  last_seen_at: string | null
  egress_since: string | null
  dropped: number
}

export type RiskBand = "hostile" | "suspicious" | "watch" | "benign"

export type Overview = {
  stats: {
    requests_24h: number
    actors_24h: number
    bands: Record<RiskBand, number>
    agents_24h: number
    pending_decisions: number
    active_decisions: number
    flagged_egress: number
  }
  llm: string // triage model, "" when off
}

export type ActorFilter = "suspicious" | "all" | "agents" | "verified" | "dismissed"

export type ActorDetail = { actor: Actor; requests: RequestEvent[]; decisions: Decision[] }

export type NewDecision = {
  actor_id?: number
  ip: string
  ja4?: string
  kind: EnforcementKind
  rpm?: number
  ttl_minutes: number
  reason?: string
}

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message)
  }
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(path, {
    method,
    credentials: "same-origin",
    headers: body === undefined ? undefined : { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  if (res.status === 204) return undefined as T
  const data: unknown = await res.json().catch(() => null)
  if (!res.ok) {
    const message =
      data && typeof data === "object" && "error" in data && typeof data.error === "string"
        ? data.error
        : `Request failed (${res.status})`
    throw new ApiError(res.status, message)
  }
  return data as T
}

export const api = {
  session: () => request<{ authenticated: boolean }>("GET", "/obs/api/session"),
  login: (token: string) => request<{ authenticated: boolean }>("POST", "/obs/api/login", { token }),
  logout: () => request<{ authenticated: boolean }>("POST", "/obs/api/logout", {}),

  overview: () => request<Overview>("GET", "/obs/api/overview"),
  actors: (filter: ActorFilter) => request<Actor[]>("GET", `/obs/api/actors?filter=${filter}`),
  actor: (id: number) => request<ActorDetail>("GET", `/obs/api/actors/${id}`),
  triage: (id: number) => request<Verdict>("POST", `/obs/api/actors/${id}/triage`, {}),
  dismiss: (id: number, dismissed: boolean) =>
    request<{ dismissed: boolean }>("POST", `/obs/api/actors/${id}/dismiss`, { dismissed }),

  decisions: () => request<Decision[]>("GET", "/obs/api/decisions"),
  createDecision: (d: NewDecision) => request<Decision>("POST", "/obs/api/decisions", d),
  transition: (id: number, verb: "approve" | "reject" | "revoke") =>
    request<Decision>("POST", `/obs/api/decisions/${id}/${verb}`, {}),

  egress: () => request<EgressDest[]>("GET", "/obs/api/egress"),

  sensors: () => request<Sensor[]>("GET", "/obs/api/sensors"),
  createSensor: (name: string) => request<{ sensor: Sensor; key: string }>("POST", "/obs/api/sensors", { name }),
  deleteSensor: (id: number) => request<void>("DELETE", `/obs/api/sensors/${id}`),
}
