import {
  Activity,
  Check,
  Copy,
  Database,
  KeyRound,
  Monitor,
  Network,
  RefreshCw,
  type LucideIcon,
} from "lucide-react"
import { Fragment, useState, type ReactNode } from "react"
import { toast } from "sonner"

import { EmptyState } from "@/components/common/empty-state"
import { LoadingSkeleton } from "@/components/common/loading-skeleton"
import { PageHeader } from "@/components/common/page-header"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Item, ItemActions, ItemContent, ItemDescription, ItemGroup, ItemSeparator, ItemTitle } from "@/components/ui/item"
import { useConfig, useVersion } from "@/hooks/use-config"
import { errorMessage } from "@/lib/api-error"
import { AUTH_UNAVAILABLE_MESSAGE } from "@/lib/auth"
import { formatAbsoluteTime, formatGoDuration } from "@/lib/format"
import type { CoreConfig, VersionInfo } from "@/lib/types"
import { cn } from "@/lib/utils"

/** One setting: what it is, what it does, its value. */
interface Row {
  label: string
  hint?: string
  value: ReactNode
}

interface Section {
  id: string
  title: string
  description: string
  icon: LucideIcon
  rows: Row[]
}

function CopyValue({ value }: { value: string }) {
  const [copied, setCopied] = useState(false)
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch {
      toast.error("The browser did not allow copying")
    }
  }
  return (
    <span className="inline-flex min-w-0 items-center gap-1">
      <span className="font-mono text-xs [overflow-wrap:anywhere]">{value}</span>
      <Button type="button" variant="ghost" size="icon" className="size-6 shrink-0" onClick={copy} aria-label={`Copy ${value}`}>
        {copied ? <Check className="size-3.5" aria-hidden /> : <Copy className="size-3.5" aria-hidden />}
      </Button>
    </span>
  )
}

function State({ on, labels = ["Enabled", "Disabled"] }: { on: boolean; labels?: [string, string] }) {
  return (
    <Badge variant="outline" className={cn("font-normal", on ? "border-status-ok/30 text-status-ok-foreground" : "text-muted-foreground")}>
      <span className={cn("size-1.5 rounded-full", on ? "bg-status-ok" : "bg-muted-foreground")} aria-hidden />
      {on ? labels[0] : labels[1]}
    </Badge>
  )
}

function Muted({ children }: { children: ReactNode }) {
  return <span className="text-sm text-muted-foreground">{children}</span>
}

function Plain({ children }: { children: ReactNode }) {
  return <span className="text-sm">{children}</span>
}

function Code({ children }: { children: ReactNode }) {
  return <span className="font-mono text-xs">{children}</span>
}

function List({ items, empty }: { items: string[]; empty: string }) {
  if (items.length === 0) return <Muted>{empty}</Muted>
  return (
    <span className="flex flex-col items-end gap-1">
      {items.map((item) => (
        <CopyValue key={item} value={item} />
      ))}
    </span>
  )
}

function address(host: string, port: number): string {
  return host ? `${host}:${port}` : `:${port}`
}

function sections(cfg: CoreConfig): Section[] {
  const tls = cfg.tls
  const db = cfg.database
  const pg = db.postgres
  const listeners: Row[] = [
    { label: "Ingestion", hint: "Where Falco posts events, with the health, version and metrics endpoints.", value: <CopyValue value={address(cfg.listen_address, cfg.listen_port)} /> },
    {
      label: "Ingestion TLS",
      hint: tls?.enabled && tls.mutual_tls ? "Clients must present a certificate signed by the client CA." : undefined,
      value: <State on={tls?.enabled === true} labels={[tls?.mutual_tls ? "Mutual TLS" : "Enabled", "Disabled"]} />,
    },
  ]
  if (tls?.enabled) {
    listeners.push({ label: "Certificate", value: tls.cert_file ? <CopyValue value={tls.cert_file} /> : <Muted>Not set</Muted> })
    listeners.push({ label: "Key", value: tls.key_file ? <CopyValue value={tls.key_file} /> : <Muted>Not set</Muted> })
    if (tls.mutual_tls) listeners.push({ label: "Client CA", value: tls.ca_file ? <CopyValue value={tls.ca_file} /> : <Muted>Not set</Muted> })
  }
  listeners.push({ label: "Management", hint: "The API and this UI.", value: <CopyValue value={address(cfg.management.listen_address, cfg.management.listen_port)} /> })

  const database: Row[] = [
    {
      label: "Backend",
      hint:
        db.backend === "inmemory"
          ? "Outputs created from the UI or the API and the pipeline layout are lost on restart."
          : "Outputs and the pipeline layout are stored here; output files are provisioned into it.",
      value: <Badge variant="secondary" className="font-mono font-normal">{db.backend}</Badge>,
    },
  ]
  if (db.backend === "sqlite") database.push({ label: "File", value: db.sqlite.path ? <CopyValue value={db.sqlite.path} /> : <Muted>Not set</Muted> })
  if (db.backend === "postgres") {
    database.push(
      { label: "Server", value: <CopyValue value={address(pg.host, pg.port)} /> },
      { label: "Database and user", value: <Code>{`${pg.database} · ${pg.user}`}</Code> },
      {
        label: "Password",
        value: pg.password_file ? (
          <CopyValue value={pg.password_file} />
        ) : pg.password ? (
          <span className="inline-flex items-center gap-1.5 text-sm text-muted-foreground">
            <KeyRound className="size-3.5" aria-hidden /> Set inline, hidden
          </span>
        ) : (
          <Muted>Not set</Muted>
        ),
      },
      { label: "SSL mode", value: <Badge variant="outline" className="font-mono font-normal">{pg.sslmode}</Badge> },
      { label: "CA file", value: pg.tls.ca_file ? <CopyValue value={pg.tls.ca_file} /> : <Muted>System CAs</Muted> },
      { label: "Connections", value: <Plain>up to {pg.max_connections}</Plain> },
      { label: "Instance sync", hint: "How often this instance checks for changes made by other instances.", value: <Plain>every {formatGoDuration(pg.poll_interval)}</Plain> },
    )
  }
  if (db.backend !== "inmemory") database.push({ label: "Connect timeout", value: <Plain>{formatGoDuration(db.connect_timeout)}</Plain> })

  return [
    { id: "listeners", title: "Listeners", description: "Where Sidekick accepts connections.", icon: Network, rows: listeners },
    { id: "database", title: "Database", description: "Where outputs and the pipeline layout are kept.", icon: Database, rows: database },
    {
      id: "api",
      title: "API and access",
      description: "What the API and the UI may change.",
      icon: KeyRound,
      rows: [
        { label: "Writes", hint: "Outputs and the layout can be changed from the UI and the API.", value: <State on={cfg.api.allow_writes} labels={["Allowed", "Read-only"]} /> },
        {
          label: "File outputs",
          hint: "Outputs defined in the output files, changed from the UI and the API.",
          value: <State on={cfg.provisioning.allow_ui_updates} labels={["Editable", "Read-only"]} />,
        },
        { label: "Secret directories", hint: "Where secret files named through the API must be.", value: <List items={cfg.api.secret_dirs} empty="None" /> },
        { label: "Authentication", hint: AUTH_UNAVAILABLE_MESSAGE, value: <State on={false} labels={["Enabled", "Not available"]} /> },
      ],
    },
    {
      id: "reload",
      title: "Reload",
      description: "How output files and secret files are followed.",
      icon: RefreshCw,
      rows: [
        {
          label: "File change poll",
          hint: "Catches changes the file watcher misses, such as Kubernetes volume swaps.",
          value: cfg.reload.poll_interval > 0 ? <Plain>every {formatGoDuration(cfg.reload.poll_interval)}</Plain> : <Muted>Off</Muted>,
        },
        { label: "Drain on reload", hint: "Longest wait for replaced and removed outputs to deliver what they hold.", value: <Plain>{formatGoDuration(cfg.reload.retire_timeout)}</Plain> },
      ],
    },
    {
      id: "observability",
      title: "Logs and metrics",
      description: "What Sidekick reports about itself.",
      icon: Activity,
      rows: [
        { label: "Log level", value: <Badge variant="outline" className="font-mono font-normal">{cfg.log_level}</Badge> },
        { label: "Log format", value: <Badge variant="outline" className="font-mono font-normal">{cfg.log_format}</Badge> },
        { label: "Extra metric labels", value: <List items={cfg.metrics.extra_labels} empty="None" /> },
        { label: "Label values", hint: "Distinct values kept per label before they are grouped.", value: <Plain>up to {cfg.metrics.max_label_values}</Plain> },
      ],
    },
    {
      id: "ui",
      title: "UI",
      description: "This interface and where it reads events.",
      icon: Monitor,
      rows: [
        { label: "UI", value: <State on={cfg.ui.enabled} /> },
        { label: "Event source", hint: "The output whose stored events the Events page and the dashboard read.", value: <Badge variant="secondary" className="font-mono font-normal">{cfg.ui.event_source}</Badge> },
      ],
    },
  ]
}

function BuildLine({ version }: { version: VersionInfo }) {
  return (
    <Card className="gap-0 py-0 shadow-xs">
      <CardContent className="flex flex-wrap items-center gap-x-6 gap-y-2 px-5 py-3 text-sm">
        <span className="flex items-center gap-2">
          <span className="text-muted-foreground">Version</span>
          <Badge className="font-mono">{version.version}</Badge>
        </span>
        <span className="flex min-w-0 items-center gap-2">
          <span className="text-muted-foreground">Commit</span>
          <CopyValue value={version.commit} />
        </span>
        <span className="flex items-center gap-2">
          <span className="text-muted-foreground">Built</span>
          {formatAbsoluteTime(version.build_date)}
        </span>
        <span className="flex items-center gap-2">
          <span className="text-muted-foreground">Go</span>
          <Code>{version.go_version}</Code>
        </span>
      </CardContent>
    </Card>
  )
}

function SectionCard({ section }: { section: Section }) {
  const Icon = section.icon
  return (
    <Card id={section.id} className="scroll-mt-4 gap-2 py-5 shadow-xs">
      <CardHeader className="px-5">
        <CardTitle className="flex items-center gap-2 text-base">
          <Icon className="size-4 text-muted-foreground" aria-hidden />
          <h2>{section.title}</h2>
        </CardTitle>
        <CardDescription>{section.description}</CardDescription>
      </CardHeader>
      <CardContent className="px-2">
        <ItemGroup>
          {section.rows.map((row, i) => (
            <Fragment key={row.label}>
              {i > 0 && <ItemSeparator />}
              <Item size="sm" role="group" aria-label={row.label} className="flex-nowrap items-start py-3">
                <ItemContent className="min-w-0">
                  <ItemTitle>{row.label}</ItemTitle>
                  {row.hint && <ItemDescription>{row.hint}</ItemDescription>}
                </ItemContent>
                <ItemActions className="max-w-[60%] justify-end text-right" data-value>
                  {row.value}
                </ItemActions>
              </Item>
            </Fragment>
          ))}
        </ItemGroup>
      </CardContent>
    </Card>
  )
}

export function ConfigurationPage() {
  const versionQuery = useVersion()
  const configQuery = useConfig()
  const failure = [versionQuery, configQuery].find((q) => q.isError)
  const version = versionQuery.data
  const cfg = configQuery.data?.config
  const all = cfg ? sections(cfg) : []

  return (
    <div className="flex h-full min-h-0 flex-col">
      <PageHeader title="Configuration" description="The running configuration, read-only. Secrets are never shown." />
      <div className="mt-4 min-h-0 flex-1 overflow-auto pr-1 pb-6">
        {failure ? (
          <EmptyState title="Unable to load the configuration" description={errorMessage(failure.error)} />
        ) : !version || !cfg ? (
          <LoadingSkeleton lines={8} />
        ) : (
          <div className="flex flex-col gap-4">
            <BuildLine version={version} />
            <div className="grid gap-6 lg:grid-cols-[11rem_minmax(0,1fr)]">
              <nav aria-label="Sections" className="hidden lg:block">
                <ul className="sticky top-0 flex flex-col gap-0.5 text-sm">
                  {all.map((s) => {
                    const Icon = s.icon
                    return (
                      <li key={s.id}>
                        <a href={`#${s.id}`} className="flex items-center gap-2 rounded-md px-2 py-1.5 text-muted-foreground transition-colors hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50">
                          <Icon className="size-4" aria-hidden />
                          {s.title}
                        </a>
                      </li>
                    )
                  })}
                </ul>
              </nav>
              <div className="flex min-w-0 flex-col gap-4">
                {all.map((s) => (
                  <SectionCard key={s.id} section={s} />
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

export default ConfigurationPage
