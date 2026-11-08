/**
 * TypeScript types mirroring the Go domain shapes exposed under /api/v1/.
 * Keep these in sync with internal/domain/{event,output,core} when the backend
 * contract changes.
 */

export type Priority =
  | "emergency"
  | "alert"
  | "critical"
  | "error"
  | "warning"
  | "notice"
  | "informational"
  | "debug"

export const PRIORITIES: readonly Priority[] = [
  "emergency",
  "alert",
  "critical",
  "error",
  "warning",
  "notice",
  "informational",
  "debug",
] as const

export const PRIORITY_LABELS: Record<Priority, string> = {
  emergency: "Emergency",
  alert: "Alert",
  critical: "Critical",
  error: "Error",
  warning: "Warning",
  notice: "Notice",
  informational: "Informational",
  debug: "Debug",
}

export function normalizePriority(p: string | undefined | null): Priority | null {
  const lower = (p ?? "").toLowerCase()
  return (PRIORITIES as readonly string[]).includes(lower) ? (lower as Priority) : null
}

export interface Event {
  uuid: string
  output: string
  priority: Priority
  rule: string
  time: string
  output_fields: Record<string, unknown>
  source: string
  tags?: string[]
  hostname?: string
}

export interface SearchResult {
  events: Event[]
  total: number
  page: number
  limit: number
}

export type OutputStatusState = "ok" | "idle" | "error" | "degraded" | "disabled" | "unknown"
export type CircuitState = "closed" | "open" | "half-open"

export interface OutputStatus {
  name: string
  status?: OutputStatusState
  queue_depth: number
  queue_capacity: number
  sent_total: number
  dropped_total: number
  failed_total: number
  events_per_minute?: number
  circuit_state: CircuitState
  last_success: string
  last_error: string
  send_latency_p99_ms?: number
}

export function statusOf(s: OutputStatus | undefined): OutputStatusState {
  return s?.status ?? "unknown"
}

export function isFlowing(s: OutputStatus | undefined): boolean {
  return s?.status === "ok"
}

export type SchemaFieldType =
  | "string"
  | "string[]"
  | "int"
  | "bool"
  | "enum"
  | "priority"
  | "map"
  | "secret"

export interface SchemaField {
  name: string
  type: SchemaFieldType
  required: boolean
  label: string
  default?: unknown
  values?: string[]
  secret?: boolean
  entry_fields?: SchemaField[]
}

export interface OutputType {
  name: string
  category: string
  schema: {
    fields: SchemaField[]
  }
}

export interface OutputConfigEntry {
  name: string
  type: string
  config: Record<string, unknown>
  /** Response-only secret presence, keyed by JSON pointers relative to config. */
  secret_fields?: Record<string, boolean>
  provisioned: boolean
  version: number
  updated_at: string
}

export interface PipelineNode {
  id: string
  kind: "source" | "sidekick" | "output"
  name: string
  type?: string
}

export interface PipelineEdge {
  id: string
  from: string
  to: string
}

export interface PipelineLayout {
  version: number
  updated_at: string
  nodes: PipelineNode[]
  edges: PipelineEdge[]
}

export interface PipelineComposite {
  outputs: OutputConfigEntry[]
  status: OutputStatus[]
  layout: PipelineLayout
}

export interface EventFilters {
  filter?: string
  priority?: Priority[]
  rule?: string[]
  source?: string[]
  hostname?: string[]
  tags?: string[]
  since?: string
}

export interface SearchQuery extends EventFilters {
  page?: number
  limit?: number
  sort_by?: "timestamp" | "priority" | "rule" | "source"
  sort_desc?: boolean
}

export interface CountByResponse {
  groups: Record<string, number>
}

export type HistogramGroupBy = "priority" | "rule" | "source" | "hostname" | "tags"

export interface HistogramRequest extends EventFilters {
  bucket_ms: number
  group_by?: HistogramGroupBy
}

export interface HistogramBucket {
  t: number
  count: number
  by?: Record<string, number>
}

export interface HistogramResult {
  buckets: HistogramBucket[]
  bucket_ms: number
  from: number
  to: number
  group_by?: HistogramGroupBy
}

export interface VersionInfo {
  version: string
  commit?: string
  date?: string
}

export interface MaskedConfig {
  config: Record<string, unknown>
  version: number
  updated_at: string
}

export interface AuthLoginResponse {
  access_token: string
  refresh_token: string
  expires_at: string
  refresh_expires_at: string
}

export interface ApiError {
  error: string
  detail?: string
}
