// Shapes of the JSON served under /api/v1, as encoded by internal/domain, internal/pipeline,
// internal/api and internal/version. The fixtures under src/test/fixtures are produced by the
// Go handlers and pin this contract.

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

export type OutputStatusState = "ok" | "idle" | "failed" | "error" | "degraded"

export const OUTPUT_STATUS_STATES: readonly OutputStatusState[] = [
  "ok",
  "idle",
  "failed",
  "error",
  "degraded",
] as const

export type CircuitState = "closed" | "open" | "half-open" | "unknown"

export const CIRCUIT_STATES: readonly CircuitState[] = ["closed", "open", "half-open", "unknown"] as const

export interface OutputStatus {
  name: string
  status: OutputStatusState
  /** Empty for an output that is not running (`failed`). */
  circuit_state: CircuitState | ""
  /** Zero time (`0001-01-01T00:00:00Z`) until the first successful delivery. */
  last_success: string
  last_error: string
  last_warning: string
  queue_depth: number
  queue_capacity: number
  sent_total: number
  dropped_total: number
  failed_total: number
  events_per_minute: number
}

/** `unknown` is UI-only: the output is configured but no status has been received for it. */
export type OutputHealth = OutputStatusState | "unknown"

export const OUTPUT_HEALTHS: readonly OutputHealth[] = [...OUTPUT_STATUS_STATES, "unknown"] as const

export function statusOf(s: OutputStatus | null | undefined): OutputHealth {
  return s?.status ?? "unknown"
}

export function isFlowing(s: OutputStatus | null | undefined): boolean {
  return s?.status === "ok"
}

const ZERO_TIME_PREFIX = "0001-01-01T"

export function isZeroTime(value: string): boolean {
  return value === "" || value.startsWith(ZERO_TIME_PREFIX)
}

export function lastSuccessOf(s: OutputStatus): string | null {
  return isZeroTime(s.last_success) ? null : s.last_success
}

/** v3 runs one output per driver, so an output's name is also its driver type. */
export function driverOf(output: { name: string }): string {
  return output.name
}

export type SchemaFieldType = "string" | "string[]" | "int" | "float" | "bool" | "enum" | "map"

export interface SchemaField {
  name: string
  type: SchemaFieldType
  label: string
  required: boolean
  default?: unknown
  values?: string[]
  secret?: boolean
  file?: boolean
  entry_fields?: SchemaField[]
}

export interface OutputType {
  name: string
  category: string
  /** True when ui.event_source may name this output type. */
  event_source?: boolean
  schema: {
    fields: SchemaField[]
  }
}

export interface OutputConfigEntry {
  name: string
  config: Record<string, unknown> | null
  /** Response-only secret presence, keyed by JSON pointers relative to config. */
  secret_fields?: Record<string, boolean>
  provisioned: boolean
  version: number
  updated_at: string
}

/** GET /api/v1/secrets: names of the files under api.secret_dirs, never their contents. */
export interface SecretsListing {
  dirs: {
    path: string
    keys: string[]
    secrets: { name: string; path: string; keys: string[] }[]
  }[]
  truncated: boolean
}

export interface LayoutNode {
  id: string
  x: number
  y: number
}

export interface PipelineLayout {
  updated_at: string
  nodes: LayoutNode[]
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

export type SortField = "timestamp" | "priority" | "rule" | "source"

export interface SearchQuery extends EventFilters {
  page?: number
  limit?: number
  sort_by?: SortField
  sort_desc?: boolean
}

export type GroupBy = "priority" | "rule" | "source" | "tags" | "hostname"

export interface CountByResponse {
  groups: Record<string, number>
}

export interface HistogramRequest extends EventFilters {
  bucket_ms: number
  group_by?: GroupBy
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
  group_by?: GroupBy
}

export interface VersionInfo {
  version: string
  commit: string
  build_date: string
  go_version: string
}

// Durations are Go time.Duration values: integer nanoseconds.
export type GoDuration = number

export interface ListenerTLSConfig {
  enabled: boolean
  mutual_tls: boolean
  cert_file: string
  key_file: string
  ca_file: string
}

export interface PostgresConfig {
  host: string
  port: number
  database: string
  user: string
  // "****" when an inline password is set; absent otherwise.
  password?: string
  password_file?: string
  sslmode: "disable" | "require" | "verify-ca" | "verify-full"
  tls: { ca_file?: string }
  max_connections: number
  poll_interval: GoDuration
}

export interface CoreConfig {
  log_format: string
  log_level: string
  listen_address: string
  listen_port: number
  tls?: ListenerTLSConfig
  management: { listen_address: string; listen_port: number }
  ui: { enabled: boolean; event_source: string }
  api: { allow_writes: boolean; secret_dirs: string[] }
  metrics: { extra_labels: string[]; max_label_values: number }
  database: {
    backend: "inmemory" | "sqlite" | "postgres"
    connect_timeout: GoDuration
    sqlite: { path: string }
    postgres: PostgresConfig
  }
  reload: { poll_interval: GoDuration; retire_timeout: GoDuration }
  provisioning: { allow_ui_updates: boolean }
}

export interface MaskedConfig {
  config: CoreConfig
}

export interface AuthLoginResponse {
  access_token: string
  refresh_token: string
  expires_at: string
  refresh_expires_at: string
}
