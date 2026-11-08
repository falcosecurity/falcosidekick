import { DRIVER_LOGOS } from "@/lib/driver-logos"
import { iconForDriver } from "@/lib/output-icons"
import type { SchemaField } from "@/lib/types"

export interface FieldSection {
  key: string
  title: string
  description?: string
  fields: SchemaField[]
  /** Sub-headings inside the section, in field order. */
  groups?: { title: string; fields: SchemaField[] }[]
}

const AUTH_FIELDS = new Set([
  "username",
  "password",
  "bearer_token",
  "api_key",
  "app_key",
  "access_key_id",
  "secret_access_key",
  "session_token",
  "role_arn",
  "external_id",
  "credentials",
])

const CONNECTION_FIELDS = new Set([
  "host",
  "hosts",
  "port",
  "base_path",
  "endpoint",
  "secret_endpoint",
  "method",
  "query_params",
  "headers",
  "tls_enabled",
  "region",
  "site",
  "brokers",
  "emulator_host",
])

const SECTION_ORDER = ["essentials", "settings", "connection", "authentication", "tls", "delivery"]

const SECTION_TEXT: Record<string, { title: string; description?: string }> = {
  essentials: { title: "Required" },
  settings: { title: "Message", description: "What is sent and how it looks." },
  connection: { title: "Connection", description: "Where events go: address, path, headers and query." },
  authentication: { title: "Authentication", description: "Credentials. On a persistent database secrets are files." },
  tls: { title: "TLS", description: "Certificates and verification of the server." },
  delivery: { title: "Delivery", description: "Queue, workers, retries, circuit breaker and batching." },
}

const DELIVERY_GROUPS: { prefix: string; title: string }[] = [
  { prefix: "runtime.retry.", title: "Retry" },
  { prefix: "runtime.circuit_breaker.", title: "Circuit breaker" },
  { prefix: "runtime.batching.", title: "Batching" },
]

function titleCase(word: string): string {
  return word.replace(/_/g, " ").replace(/^\w/, (c) => c.toUpperCase())
}

function sectionOf(field: SchemaField): string {
  if (field.required) return "essentials"
  const [head] = field.name.split(".")
  if (field.name.startsWith("runtime.")) return "delivery"
  if (field.name.startsWith("tls.")) return "tls"
  if (field.name.startsWith("auth.") || AUTH_FIELDS.has(field.name) || field.secret) return "authentication"
  if (CONNECTION_FIELDS.has(field.name)) return "connection"
  if (field.name.includes(".")) return head!
  return "settings"
}

/** Splits a driver's fields into the wizard's sections, required fields first. */
export function sectionsFor(fields: readonly SchemaField[]): FieldSection[] {
  const byKey = new Map<string, SchemaField[]>()
  for (const field of fields) {
    const key = sectionOf(field)
    byKey.set(key, [...(byKey.get(key) ?? []), field])
  }
  const keys = [...byKey.keys()].sort((a, b) => {
    const ia = SECTION_ORDER.indexOf(a)
    const ib = SECTION_ORDER.indexOf(b)
    // Driver-specific groups such as producer or traces come after the common ones, before delivery.
    const ra = ia === -1 ? SECTION_ORDER.indexOf("tls") + 0.5 : ia
    const rb = ib === -1 ? SECTION_ORDER.indexOf("tls") + 0.5 : ib
    return ra - rb || a.localeCompare(b)
  })
  return keys.map((key) => {
    const sectionFields = byKey.get(key)!
    const text = SECTION_TEXT[key] ?? { title: titleCase(key) }
    const section: FieldSection = { key, ...text, fields: sectionFields }
    if (key === "delivery") {
      const general = sectionFields.filter((f) => !DELIVERY_GROUPS.some((g) => f.name.startsWith(g.prefix)))
      section.groups = [
        { title: "Queue and workers", fields: general },
        ...DELIVERY_GROUPS.map((g) => ({ title: g.title, fields: sectionFields.filter((f) => f.name.startsWith(g.prefix)) })),
      ].filter((g) => g.fields.length > 0)
    }
    return section
  })
}

const DRIVER_TITLES: Record<string, string> = {
  alertmanager: "Alertmanager",
  cloudevents: "CloudEvents",
  gcppubsub: "Google Pub/Sub",
  grafanaoncall: "Grafana OnCall",
  inmemory: "In-memory store",
  loki: "Loki",
  otlp: "OpenTelemetry (OTLP)",
  policyreport: "Policy Report",
  smtp: "Email (SMTP)",
  syslog: "Syslog",
  talon: "Falco Talon",
  webhook: "Webhook",
}

/** The name shown for a driver: its product name, the logo title when it is the driver's own. */
export function driverTitle(driver: string): string {
  if (DRIVER_TITLES[driver]) return DRIVER_TITLES[driver]
  const icon = iconForDriver(driver)
  if (icon.kind === "logo" && icon.official) return DRIVER_LOGOS[icon.logo].title
  if (icon.kind === "asset") return icon.title
  return titleCase(driver)
}

const CATEGORY_TITLES: Record<string, string> = {
  alerting: "Alerting and on-call",
  chat: "Chat",
  email: "Email",
  logging: "Logging",
  logs: "Logs",
  observability: "Observability",
  other: "Other",
  queue: "Queues and streams",
  response: "Response",
  storage: "Storage",
  store: "Store",
  webhook: "Webhooks",
}

export function categoryTitle(category: string): string {
  return CATEGORY_TITLES[category] ?? titleCase(category)
}

/** A short hint under the field: the default, or what a file field expects. */
export function fieldHint(field: SchemaField): string | undefined {
  if (field.file) return "Absolute path of a file"
  if (field.default === undefined || field.default === null || field.default === "") return undefined
  return `Default ${Array.isArray(field.default) ? field.default.join(", ") : String(field.default)}`
}
