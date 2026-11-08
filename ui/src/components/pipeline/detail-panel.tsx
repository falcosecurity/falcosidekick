import { useQuery } from "@tanstack/react-query"
import { Server } from "lucide-react"

import falcoIcon from "@/assets/falco-icon.svg"
import { ConfigTree } from "@/components/common/config-tree"
import { EmptyState } from "@/components/common/empty-state"
import { LoadingSkeleton } from "@/components/common/loading-skeleton"
import { Meter } from "@/components/common/meter"
import { OutputTypeIcon } from "@/components/common/output-type-icon"
import { SectionHeading } from "@/components/common/section-heading"
import { StatTile } from "@/components/common/stat-tile"
import { StatusBadge } from "@/components/common/status-badge"
import { TimeAgo } from "@/components/common/time-ago"
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Separator } from "@/components/ui/separator"
import { useConfig, useVersion } from "@/hooks/use-config"
import { useOutputs } from "@/hooks/use-pipeline"
import { useRefetchInterval } from "@/hooks/use-refetch-interval"
import { api } from "@/lib/api-client"
import { errorMessage } from "@/lib/api-error"
import { formatAbsoluteTime, formatNumber } from "@/lib/format"
import { driverOf, lastSuccessOf, statusOf, type OutputConfigEntry, type OutputStatus } from "@/lib/types"
import { queueTone } from "@/components/dashboard/output-status-grid"

import type { PipelineSelection } from "./canvas"

interface DetailPanelProps {
  selection: PipelineSelection
  entry: OutputConfigEntry | null
  status: OutputStatus | null
}

export function PipelineDetailPanel({ selection, entry, status }: DetailPanelProps) {
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
  return <OutputDetail entry={entry} status={status} />
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
    return <EmptyState title="Unable to load pipeline details" description={errorMessage(failure.error)} />
  }
  const version = versionQuery.data
  const config = configQuery.data?.config
  const outputs = outputsQuery.data
  if (!version || !config || !outputs) {
    return <LoadingSkeleton lines={5} />
  }

  const listenAddress = (config["listen_address"] as string | undefined) ?? ""
  const listenPort = (config["listen_port"] as number | undefined) ?? 2801
  const logLevel = (config["log_level"] as string | undefined) ?? ""
  const database = (config["database"] as { backend?: string } | undefined)?.backend ?? ""

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

function OutputDetail({ entry, status }: { entry: OutputConfigEntry | null; status: OutputStatus | null }) {
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
                {entry.provisioned ? "from output files" : "created through the API"}
              </CardDescription>
            </div>
          </div>
          {status && <StatusBadge status={statusOf(status)} />}
        </div>
      </CardHeader>
      <ScrollArea className="min-h-0 min-w-0 flex-1 px-6 pb-6">
        {status && (
          <section className="flex flex-col gap-2">
            <SectionHeading>Health</SectionHeading>
            <dl className="grid grid-cols-2 gap-2 text-sm">
              <StatTile label="Sent" value={formatNumber(status.sent_total)} tone="ok" />
              <StatTile
                label="Failed"
                value={formatNumber(status.failed_total)}
                tone={status.failed_total > 0 ? "error" : "neutral"}
              />
              <StatTile
                label="Dropped"
                value={formatNumber(status.dropped_total)}
                tone={status.dropped_total > 0 ? "warning" : "neutral"}
              />
              <StatTile
                label="Queue"
                value={`${status.queue_depth} / ${status.queue_capacity}`}
                tone={queueTone(status.queue_depth, status.queue_capacity)}
              >
                <Meter
                  value={status.queue_depth}
                  max={status.queue_capacity}
                  label={`Queue ${status.name}`}
                  tone={queueTone(status.queue_depth, status.queue_capacity) === "warning" ? "warning" : "brand"}
                  className="mt-1"
                />
              </StatTile>
              <StatTile label="Evt/min" value={formatNumber(Math.round(status.events_per_minute))} />
              <StatTile
                label="Circuit"
                value={status.circuit_state || "-"}
                tone={status.circuit_state === "open" || status.circuit_state === "half-open" ? "warning" : "neutral"}
              />
              <StatTile label="Last success" className="col-span-2" valueClassName="font-normal">
                {lastSuccess ? <TimeAgo value={lastSuccess} /> : "never"}
              </StatTile>
            </dl>
            {status.last_error && (
              <div className="mt-2 flex flex-col gap-1">
                <SectionHeading className="text-2xs text-status-error-foreground">Last error</SectionHeading>
                <div className="rounded-md border border-status-error/30 bg-status-error/10 px-2 py-1.5 font-mono text-xs text-status-error-foreground [overflow-wrap:anywhere]">
                  {status.last_error}
                </div>
              </div>
            )}
            {status.last_warning && (
              <div className="mt-2 flex flex-col gap-1">
                <SectionHeading className="text-2xs text-status-degraded-foreground">Last warning</SectionHeading>
                <div className="rounded-md border border-status-degraded/30 bg-status-degraded/10 px-2 py-1.5 font-mono text-xs text-status-degraded-foreground [overflow-wrap:anywhere]">
                  {status.last_warning}
                </div>
              </div>
            )}
          </section>
        )}

        {isInmemory && inmemoryCapacity != null && (
          <>
            {status && <Separator className="my-4" />}
            <section className="flex flex-col gap-2">
              <SectionHeading>Ring buffer</SectionHeading>
              {eventsCountQuery.isError ? (
                <EmptyState title="Unable to load ring-buffer usage" description={errorMessage(eventsCountQuery.error)} />
              ) : eventsCountQuery.isPending ? (
                <LoadingSkeleton lines={2} />
              ) : (
                <BufferUsage used={eventsCountQuery.data} capacity={inmemoryCapacity} />
              )}
            </section>
          </>
        )}

        <Separator className="my-4" />

        <section className="flex flex-col gap-2">
          <SectionHeading>Configuration (masked)</SectionHeading>
          <ConfigTree data={entry.config ?? {}} secretFields={entry.secret_fields} />
        </section>
      </ScrollArea>
    </Card>
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
