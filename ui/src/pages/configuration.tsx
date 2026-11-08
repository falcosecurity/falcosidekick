import type { ReactNode } from "react"

import { EmptyState } from "@/components/common/empty-state"
import { LoadingSkeleton } from "@/components/common/loading-skeleton"
import { PageHeader } from "@/components/common/page-header"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { useConfig, useVersion } from "@/hooks/use-config"
import { errorMessage } from "@/lib/api-error"
import { AUTH_UNAVAILABLE_MESSAGE } from "@/lib/auth"
import { formatAbsoluteTime, formatGoDuration } from "@/lib/format"
import type { CoreConfig, PostgresConfig, VersionInfo } from "@/lib/types"

interface Row {
  term: string
  value: ReactNode
  mono?: boolean
}

function Section({ title, description, rows }: { title: string; description?: string; rows: Row[] }) {
  return (
    <Card className="min-w-0">
      <CardHeader>
        <CardTitle asChild className="text-base">
          <h2>{title}</h2>
        </CardTitle>
        {description && <CardDescription>{description}</CardDescription>}
      </CardHeader>
      <CardContent>
        <dl className="grid grid-cols-[minmax(7rem,auto)_1fr] gap-x-4 gap-y-2 text-sm">
          {rows.map((row) => (
            <div key={row.term} className="contents">
              <dt className="text-muted-foreground">{row.term}</dt>
              <dd className={row.mono ? "font-mono text-xs leading-5 [overflow-wrap:anywhere]" : "[overflow-wrap:anywhere]"}>
                {row.value}
              </dd>
            </div>
          ))}
        </dl>
      </CardContent>
    </Card>
  )
}

// Empty values read as words, not as technical values, even inside a monospaced row.
const EMPTY_VALUE = "font-sans text-sm text-muted-foreground"

function NotSet() {
  return <span className={EMPTY_VALUE}>Not set</span>
}

function pathOrNotSet(path: string | undefined): ReactNode {
  return path ? path : <NotSet />
}

function List({ items, empty }: { items: string[]; empty: string }) {
  if (items.length === 0) return <span className={EMPTY_VALUE}>{empty}</span>
  return (
    <ul className="flex flex-col gap-0.5">
      {items.map((item) => (
        <li key={item}>{item}</li>
      ))}
    </ul>
  )
}

function address(host: string, port: number): string {
  return host ? `${host}:${port}` : `:${port}`
}

function onOff(value: boolean): string {
  return value ? "Enabled" : "Disabled"
}

function postgresPassword(pg: PostgresConfig): ReactNode {
  if (pg.password_file) return <span className="font-mono text-xs">{pg.password_file}</span>
  if (pg.password) return "Set inline (masked)"
  return <NotSet />
}

function buildRows(version: VersionInfo): Row[] {
  return [
    { term: "Version", value: version.version, mono: true },
    { term: "Commit", value: version.commit, mono: true },
    { term: "Built", value: formatAbsoluteTime(version.build_date) },
    { term: "Go", value: version.go_version, mono: true },
  ]
}

function listenerRows(cfg: CoreConfig): Row[] {
  const tls = cfg.tls
  const rows: Row[] = [
    { term: "Ingestion", value: address(cfg.listen_address, cfg.listen_port), mono: true },
    {
      term: "Ingestion TLS",
      value: tls?.enabled ? (tls.mutual_tls ? "Enabled, mutual TLS" : "Enabled") : "Disabled",
    },
  ]
  if (tls?.enabled) {
    rows.push(
      { term: "Certificate", value: pathOrNotSet(tls.cert_file), mono: true },
      { term: "Key", value: pathOrNotSet(tls.key_file), mono: true },
    )
    if (tls.mutual_tls) rows.push({ term: "Client CA", value: pathOrNotSet(tls.ca_file), mono: true })
  }
  rows.push({ term: "Management", value: address(cfg.management.listen_address, cfg.management.listen_port), mono: true })
  return rows
}

function databaseRows(cfg: CoreConfig): Row[] {
  const db = cfg.database
  const rows: Row[] = [{ term: "Backend", value: db.backend, mono: true }]
  if (db.backend === "sqlite") {
    rows.push({ term: "Path", value: pathOrNotSet(db.sqlite.path), mono: true })
  }
  if (db.backend === "postgres") {
    const pg = db.postgres
    rows.push(
      { term: "Server", value: address(pg.host, pg.port), mono: true },
      { term: "Database", value: pg.database, mono: true },
      { term: "User", value: pg.user, mono: true },
      { term: "Password", value: postgresPassword(pg) },
      { term: "SSL mode", value: pg.sslmode, mono: true },
      { term: "CA file", value: pathOrNotSet(pg.tls.ca_file), mono: true },
      { term: "Connections", value: `up to ${pg.max_connections}` },
      { term: "Instance sync", value: `checks for changes by other instances every ${formatGoDuration(pg.poll_interval)}` },
    )
  }
  if (db.backend !== "inmemory") {
    rows.push({ term: "Connect timeout", value: formatGoDuration(db.connect_timeout) })
  }
  return rows
}

function databaseDescription(backend: CoreConfig["database"]["backend"]): string {
  return backend === "inmemory"
    ? "Outputs created from the UI or the API and the pipeline layout are kept in memory and lost on restart."
    : "Outputs and the pipeline layout are stored here; output files are provisioned into it."
}

function apiRows(cfg: CoreConfig): Row[] {
  return [
    { term: "Writes", value: cfg.api.allow_writes ? "Allowed" : "Read-only" },
    { term: "Secret directories", value: <List items={cfg.api.secret_dirs} empty="None" />, mono: true },
    { term: "Authentication", value: AUTH_UNAVAILABLE_MESSAGE },
  ]
}

function outputRows(cfg: CoreConfig): Row[] {
  return [
    {
      term: "File outputs",
      value: cfg.provisioning.allow_ui_updates ? "Editable from the UI and the API" : "Read-only from the UI and the API",
    },
    {
      term: "File change poll",
      value: cfg.reload.poll_interval > 0 ? `every ${formatGoDuration(cfg.reload.poll_interval)}` : "Off",
    },
    { term: "Drain on reload", value: `up to ${formatGoDuration(cfg.reload.retire_timeout)} for replaced and removed outputs` },
  ]
}

function observabilityRows(cfg: CoreConfig): Row[] {
  return [
    { term: "Log level", value: cfg.log_level, mono: true },
    { term: "Log format", value: cfg.log_format, mono: true },
    { term: "Metric labels", value: <List items={cfg.metrics.extra_labels} empty="None" />, mono: true },
    { term: "Label values", value: `up to ${cfg.metrics.max_label_values} per label` },
  ]
}

function uiRows(cfg: CoreConfig): Row[] {
  return [
    { term: "UI", value: onOff(cfg.ui.enabled) },
    { term: "Event source", value: cfg.ui.event_source, mono: true },
  ]
}

export function ConfigurationPage() {
  const versionQuery = useVersion()
  const configQuery = useConfig()
  const failure = [versionQuery, configQuery].find((q) => q.isError)
  const version = versionQuery.data
  const cfg = configQuery.data?.config

  return (
    <div className="flex h-full min-h-0 flex-col">
      <PageHeader
        title="Configuration"
        description="The running configuration, read-only. Secrets are masked."
      />
      <div className="mt-4 min-h-0 flex-1 overflow-auto pr-1">
        {failure ? (
          <EmptyState title="Unable to load the configuration" description={errorMessage(failure.error)} />
        ) : !version || !cfg ? (
          <LoadingSkeleton lines={8} />
        ) : (
          <div className="grid content-start gap-4 lg:grid-cols-2">
            <Section title="Build" rows={buildRows(version)} />
            <Section title="Listeners" rows={listenerRows(cfg)} />
            <Section title="Database" description={databaseDescription(cfg.database.backend)} rows={databaseRows(cfg)} />
            <Section title="API" rows={apiRows(cfg)} />
            <Section title="Outputs" rows={outputRows(cfg)} />
            <Section title="Logs and metrics" rows={observabilityRows(cfg)} />
            <Section title="UI" rows={uiRows(cfg)} />
          </div>
        )}
      </div>
    </div>
  )
}

export default ConfigurationPage
