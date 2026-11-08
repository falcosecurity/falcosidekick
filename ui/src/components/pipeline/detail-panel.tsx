import { useQuery } from "@tanstack/react-query"
import { AlertTriangle, Pencil, Server, Trash2 } from "lucide-react"
import type { ReactNode } from "react"

import falcoIcon from "@/assets/falco-icon.svg"
import { ConfigTree } from "@/components/common/config-tree"
import { ErrorState } from "@/components/common/error-state"
import { LoadingSkeleton } from "@/components/common/loading-skeleton"
import { Meter } from "@/components/common/meter"
import { OriginMark } from "@/components/common/origin-mark"
import { OutputTypeIcon } from "@/components/common/output-type-icon"
import { SectionHeading } from "@/components/common/section-heading"
import { StatTile } from "@/components/common/stat-tile"
import { StatusBadge } from "@/components/common/status-badge"
import { TimeAgo } from "@/components/common/time-ago"
import { queueTone } from "@/components/dashboard/attention"
import { OutputConfigView } from "@/components/outputs/output-config-view"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Separator } from "@/components/ui/separator"
import { useConfig, useVersion } from "@/hooks/use-config"
import { useOutputTypes } from "@/hooks/use-output-writes"
import { useOutputs } from "@/hooks/use-pipeline"
import { useRefetchInterval } from "@/hooks/use-refetch-interval"
import { api } from "@/lib/api-client"
import { errorMessage } from "@/lib/api-error"
import { formatAbsoluteTime, formatNumber } from "@/lib/format"
import { driverOf, lastSuccessOf, statusOf, type OutputConfigEntry, type OutputStatus } from "@/lib/types"
import { cn } from "@/lib/utils"

import type { PipelineSelection } from "./canvas"

/** Present only when the API allows changing the selected output. */
export interface OutputActions {
  onEdit: () => void
  onDelete: () => void
}

interface DetailPanelProps {
  selection: PipelineSelection
  entry: OutputConfigEntry | null
  status: OutputStatus | null
  actions?: OutputActions
}

export function PipelineDetailPanel({ selection, entry, status, actions }: DetailPanelProps) {
  if (!selection) {
    return (
      <Card className="h-full min-w-0">
        <CardHeader className="min-w-0">
          <CardTitle asChild className="text-base">
            <h2>Detail</h2>
          </CardTitle>
          <CardDescription>Select any node in the pipeline to see its details.</CardDescription>
        </CardHeader>
      </Card>
    )
  }
  if (selection.kind === "source") return <SourceDetail />
  if (selection.kind === "core") return <CoreDetail />
  return <OutputDetail entry={entry} status={status} actions={actions} />
}

function SourceDetail() {
  return (
    <Card className="flex h-full min-h-0 min-w-0 flex-col">
      <CardHeader className="min-w-0 shrink-0">
        <div className="flex items-center gap-3">
          <span className="flex size-10 items-center justify-center rounded-md bg-brand/15">
            <img src={falcoIcon} alt="" aria-hidden className="size-6" />
          </span>
          <div>
            <CardTitle asChild className="text-base">
              <h2>Falco</h2>
            </CardTitle>
            <CardDescription>event source</CardDescription>
          </div>
        </div>
      </CardHeader>
      <ScrollArea className="min-h-0 min-w-0 flex-1 px-6 pb-6">
        <section className="flex flex-col gap-2 text-sm">
          <p>Falco sends events to this falcosidekick instance over HTTP.</p>
          <p className="text-muted-foreground">
            Falco's <code className="rounded bg-muted px-1 py-0.5 font-mono text-xs">http_output</code> posts
            detected events as JSON to <code className="rounded bg-muted px-1 py-0.5 font-mono text-xs">POST /</code> on
            this server. There is no outbound connection from falcosidekick to Falco; the arrow above represents
            the inbound event flow.
          </p>
        </section>
        <Separator className="my-4" />
        <section className="flex flex-col gap-2 text-sm">
          <SectionHeading>Endpoint</SectionHeading>
          <code className="block rounded bg-muted p-2 font-mono text-xs">POST /</code>
          <p className="text-xs text-muted-foreground">
            Point your Falco <code>http_output.url</code> at this host and port.
          </p>
        </section>
      </ScrollArea>
    </Card>
  )
}

function CoreDetail() {
  const versionQuery = useVersion()
  const configQuery = useConfig()
  const outputsQuery = useOutputs()

  const failure = [versionQuery, configQuery, outputsQuery].find((q) => q.isError)
  if (failure) {
    return <ErrorState title="Unable to load pipeline details" description={errorMessage(failure.error)} />
  }
  const version = versionQuery.data
  const config = configQuery.data?.config
  const outputs = outputsQuery.data
  if (!version || !config || !outputs) {
    return <LoadingSkeleton lines={5} />
  }

  const listenAddress = config.listen_address
  const listenPort = config.listen_port
  const logLevel = config.log_level
  const database = config.database.backend

  return (
    <Card className="flex h-full min-h-0 min-w-0 flex-col">
      <CardHeader className="min-w-0 shrink-0">
        <div className="flex items-center gap-3">
          <span className="flex size-10 items-center justify-center rounded-md bg-brand/15 text-brand">
            <Server className="size-5" aria-hidden />
          </span>
          <div>
            <CardTitle asChild className="text-base">
              <h2>Falco Sidekick</h2>
            </CardTitle>
            <CardDescription>event pipeline</CardDescription>
          </div>
        </div>
      </CardHeader>
      <ScrollArea className="min-h-0 min-w-0 flex-1 px-6 pb-6">
        <section className="flex flex-col gap-2">
          <SectionHeading>Build</SectionHeading>
          <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
            <dt className="text-muted-foreground">Version</dt>
            <dd className="font-mono [overflow-wrap:anywhere]">{version.version}</dd>
            <dt className="text-muted-foreground">Commit</dt>
            <dd className="font-mono text-xs [overflow-wrap:anywhere]">{version.commit}</dd>
            <dt className="text-muted-foreground">Built</dt>
            <dd className="font-mono text-xs">{formatAbsoluteTime(version.build_date)}</dd>
            <dt className="text-muted-foreground">Go</dt>
            <dd className="font-mono text-xs">{version.go_version}</dd>
          </dl>
        </section>
        <Separator className="my-4" />
        <section className="flex flex-col gap-2">
          <SectionHeading>Runtime</SectionHeading>
          <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
            <dt className="text-muted-foreground">Listen</dt>
            <dd className="font-mono">{listenAddress ? `${listenAddress}:${listenPort}` : `:${listenPort}`}</dd>
            {logLevel && (
              <>
                <dt className="text-muted-foreground">Log level</dt>
                <dd className="font-mono">{logLevel}</dd>
              </>
            )}
            {database && (
              <>
                <dt className="text-muted-foreground">Database</dt>
                <dd className="font-mono">{database}</dd>
              </>
            )}
            <dt className="text-muted-foreground">Outputs</dt>
            <dd>{outputs.length}</dd>
          </dl>
        </section>
      </ScrollArea>
    </Card>
  )
}

function OutputDetail({
  entry,
  status,
  actions,
}: {
  entry: OutputConfigEntry | null
  status: OutputStatus | null
  actions?: OutputActions
}) {
  const types = useOutputTypes()
  const isInmemory = entry?.name === "inmemory"
  const inmemoryCapacity = typeof entry?.config?.["capacity"] === "number" ? entry.config["capacity"] : undefined
  const refetchInterval = useRefetchInterval()

  const eventsCountQuery = useQuery({
    queryKey: ["events", "count", "for-inmemory"],
    queryFn: ({ signal }) => api.countEvents({}, signal),
    enabled: isInmemory,
    refetchInterval: isInmemory ? refetchInterval : false,
  })

  if (!entry) {
    return (
      <Card className="h-full min-w-0">
        <CardHeader className="min-w-0">
          <CardTitle asChild className="text-base">
            <h2>Output detail</h2>
          </CardTitle>
          <CardDescription>Output not found.</CardDescription>
        </CardHeader>
      </Card>
    )
  }
  const lastSuccess = status ? lastSuccessOf(status) : null
  const outputType = types.data?.find((t) => t.name === entry.name)
  return (
    <Card className="flex h-full min-h-0 min-w-0 flex-col">
      <CardHeader className="min-w-0 shrink-0">
        <div className="flex min-w-0 flex-wrap items-start justify-between gap-3">
          <div className="flex min-w-0 flex-1 basis-40 items-center gap-3">
            <OutputTypeIcon driver={driverOf(entry)} />
            <div className="min-w-0">
              <CardTitle asChild className="text-base leading-normal [overflow-wrap:anywhere]">
                <h2>{entry.name}</h2>
              </CardTitle>
              <CardDescription className="[overflow-wrap:anywhere]">
                <OriginMark provisioned={entry.provisioned} showLabel />
              </CardDescription>
            </div>
          </div>
          {status && <StatusBadge status={statusOf(status)} />}
        </div>
        {actions && (
          <div className="flex gap-2 pt-2">
            <Button type="button" variant="outline" size="sm" onClick={actions.onEdit}>
              <Pencil className="size-3.5" aria-hidden /> Edit
            </Button>
            <Button type="button" variant="ghost" size="sm" className="text-destructive hover:bg-destructive/10 hover:text-destructive" onClick={actions.onDelete}>
              <Trash2 className="size-3.5" aria-hidden /> Remove
            </Button>
          </div>
        )}
      </CardHeader>
      <ScrollArea className="min-h-0 min-w-0 flex-1 px-6 pb-6">
        {status && <OutputProblem status={status} />}
        {status && (
          <section className="flex flex-col gap-3" aria-label="Health">
            <dl className="grid grid-cols-3 gap-2 text-sm">
              <StatTile label="Sent" value={formatNumber(status.sent_total)} tone="ok" />
              <StatTile label="Failed" value={formatNumber(status.failed_total)} tone={status.failed_total > 0 ? "error" : "neutral"} />
              <StatTile label="Dropped" value={formatNumber(status.dropped_total)} tone={status.dropped_total > 0 ? "warning" : "neutral"} />
            </dl>
            <dl className="flex flex-col gap-2 rounded-lg border bg-background px-3 py-2.5 text-sm">
              <div className="flex flex-col gap-1.5">
                <div className="flex items-baseline justify-between gap-2">
                  <dt className="text-muted-foreground">Queue</dt>
                  <dd className="tabular-nums">
                    {formatNumber(status.queue_depth)} / {formatNumber(status.queue_capacity)}
                  </dd>
                </div>
                <Meter
                  value={status.queue_depth}
                  max={status.queue_capacity}
                  label={`Queue ${status.name}`}
                  tone={queueTone(status.queue_depth, status.queue_capacity) === "warning" ? "warning" : "brand"}
                  decorative
                />
              </div>
              <HealthRow term="Circuit breaker">
                <span className={status.circuit_state === "open" || status.circuit_state === "half-open" ? "text-status-degraded-foreground" : undefined}>
                  {status.circuit_state || "not running"}
                </span>
              </HealthRow>
              <HealthRow term="Rate">{formatNumber(Math.round(status.events_per_minute))} events/min</HealthRow>
              <HealthRow term="Last delivery">{lastSuccess ? <TimeAgo value={lastSuccess} /> : "never"}</HealthRow>
            </dl>
          </section>
        )}

        {isInmemory && inmemoryCapacity != null && (
          <>
            {status && <Separator className="my-4" />}
            <section className="flex flex-col gap-2">
              <SectionHeading>Ring buffer</SectionHeading>
              {eventsCountQuery.isError ? (
                <ErrorState title="Unable to load ring-buffer usage" description={errorMessage(eventsCountQuery.error)} />
              ) : eventsCountQuery.isPending ? (
                <LoadingSkeleton lines={2} />
              ) : (
                <BufferUsage used={eventsCountQuery.data} capacity={inmemoryCapacity} />
              )}
            </section>
          </>
        )}

        <Separator className="my-4" />

        {types.isPending ? (
          <LoadingSkeleton lines={4} />
        ) : outputType ? (
          <OutputConfigView key={entry.name} entry={entry} fields={outputType.schema.fields} />
        ) : (
          <section className="flex flex-col gap-2">
            <SectionHeading>Configuration</SectionHeading>
            <ConfigTree data={entry.config ?? {}} secretFields={entry.secret_fields} />
          </section>
        )}
      </ScrollArea>
    </Card>
  )
}

function HealthRow({ term, children }: { term: string; children: ReactNode }) {
  return (
    <div className="flex items-baseline justify-between gap-2">
      <dt className="text-muted-foreground">{term}</dt>
      <dd className="text-right">{children}</dd>
    </div>
  )
}

/**
 * The output's problem, one cause: the last delivery error, or the warning when there is no error.
 * The start-up check warning is added only when it says something the error does not.
 */
export function problemOf(status: OutputStatus): { main: string; extra?: string } | null {
  const error = status.last_error
  const warning = status.last_warning
  if (error) return warning && !warning.includes(error) ? { main: error, extra: warning } : { main: error }
  if (warning) return { main: warning }
  return null
}

function OutputProblem({ status }: { status: OutputStatus }) {
  const problem = problemOf(status)
  if (!problem) return null
  const error = status.last_error !== ""
  return (
    <Alert variant={error ? "destructive" : "default"} className={cn("mb-4", !error && "border-status-degraded/40 text-status-degraded-foreground")}>
      <AlertTriangle aria-hidden />
      <AlertTitle>{error ? "Not delivering" : "Needs a look"}</AlertTitle>
      <AlertDescription>
        <p className="font-mono text-xs [overflow-wrap:anywhere]">{problem.main}</p>
        {problem.extra && <p className="text-xs [overflow-wrap:anywhere]">Also: {problem.extra}</p>}
      </AlertDescription>
    </Alert>
  )
}

function BufferUsage({ used, capacity }: { used: number; capacity: number }) {
  const pct = capacity > 0 ? Math.min(100, (used / capacity) * 100) : 0
  return (
    <div className="flex flex-col gap-1.5">
      <div className="flex flex-wrap items-baseline justify-between gap-x-2 text-sm">
        <span className="text-muted-foreground">Events stored</span>
        <span className="font-medium tabular-nums">
          {formatNumber(used)} / {formatNumber(capacity)}
        </span>
      </div>
      <Meter value={used} max={capacity} label="Events stored" size="md" tone={pct > 90 ? "warning" : "ok"} />
      <div className="text-xs text-muted-foreground">
        {pct.toFixed(1)}% of ring capacity.
        {pct >= 100 && " Oldest events are being overwritten."}
      </div>
    </div>
  )
}
