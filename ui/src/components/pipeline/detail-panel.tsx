import { useQuery } from "@tanstack/react-query"
import { Server } from "lucide-react"

import falcoIcon from "@/assets/falco-icon.svg"
import { ConfigTree } from "@/components/common/config-tree"
import { EmptyState } from "@/components/common/empty-state"
import { LoadingSkeleton } from "@/components/common/loading-skeleton"
import { OutputTypeIcon } from "@/components/common/output-type-icon"
import { StatusBadge } from "@/components/common/status-badge"
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Separator } from "@/components/ui/separator"
import { api } from "@/lib/api-client"
import { formatDurationMs, formatNumber } from "@/lib/format"
import { cn } from "@/lib/utils"
import { statusOf, type OutputConfigEntry, type OutputStatus } from "@/lib/types"
import { useUIStore } from "@/stores/ui-store"

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
          <CardTitle className="text-base">Detail</CardTitle>
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
            <CardTitle className="text-base">Falco</CardTitle>
            <CardDescription>event source</CardDescription>
          </div>
        </div>
      </CardHeader>
      <ScrollArea className="min-h-0 min-w-0 flex-1 px-6 pb-6">
        <section className="flex flex-col gap-2 text-sm">
          <p>
            Falco sends events to this falcosidekick instance over HTTP.
          </p>
          <p className="text-muted-foreground">
            Falco's <code className="rounded bg-muted px-1 py-0.5 font-mono text-xs">http_output</code>{" "}
            posts detected events as JSON to <code className="rounded bg-muted px-1 py-0.5 font-mono text-xs">POST /</code>{" "}
            on this server. There is no outbound connection from falcosidekick to Falco; the arrow
            above represents the inbound event flow.
          </p>
        </section>
        <Separator className="my-4" />
        <section className="flex flex-col gap-2 text-sm">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Endpoint
          </h3>
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
  const refreshIntervalMs = useUIStore((s) => s.refreshIntervalMs)
  const refetchInterval = refreshIntervalMs > 0 ? refreshIntervalMs : false
  const versionQuery = useQuery({
    queryKey: ["version"],
    queryFn: ({ signal }) => api.getVersion(signal),
  })
  const configQuery = useQuery({
    queryKey: ["config"],
    queryFn: ({ signal }) => api.getConfig(signal),
    refetchInterval,
  })
  const outputsQuery = useQuery({
    queryKey: ["pipeline", "outputs"],
    queryFn: ({ signal }) => api.getOutputs(signal),
    refetchInterval,
  })

  if (versionQuery.isError || configQuery.isError || outputsQuery.isError) {
    return <EmptyState title="Unable to load pipeline details" />
  }
  if (versionQuery.isPending || configQuery.isPending || outputsQuery.isPending) {
    return <LoadingSkeleton lines={5} />
  }
  const version = versionQuery.data
  const maskedConfig = configQuery.data
  const outputs = outputsQuery.data

  const listenAddress =
    (maskedConfig?.config?.["listen_address"] as string | undefined) ?? ""
  const listenPort =
    (maskedConfig?.config?.["listen_port"] as number | undefined) ?? 2801
  const logLevel = (maskedConfig?.config?.["log_level"] as string | undefined) ?? ""
  const database =
    (maskedConfig?.config?.["database"] as { backend?: string } | undefined)?.backend ?? ""

  return (
    <Card className="flex h-full min-h-0 min-w-0 flex-col">
      <CardHeader className="min-w-0 shrink-0">
        <div className="flex items-center gap-3">
          <span className="flex size-10 items-center justify-center rounded-md bg-brand/15 text-brand">
            <Server className="size-5" aria-hidden />
          </span>
          <div>
            <CardTitle className="text-base">Falco Sidekick</CardTitle>
            <CardDescription>event pipeline</CardDescription>
          </div>
        </div>
      </CardHeader>
      <ScrollArea className="min-h-0 min-w-0 flex-1 px-6 pb-6">
        <section className="flex flex-col gap-2">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Build
          </h3>
          <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
            <dt className="text-muted-foreground">Version</dt>
            <dd className="font-mono">{version?.version ?? "unknown"}</dd>
            {version?.commit && (
              <>
                <dt className="text-muted-foreground">Commit</dt>
                <dd className="truncate font-mono text-xs">{version.commit}</dd>
              </>
            )}
          </dl>
        </section>
        <Separator className="my-4" />
        <section className="flex flex-col gap-2">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Runtime
          </h3>
          <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
            <dt className="text-muted-foreground">Listen</dt>
            <dd className="font-mono">
              {listenAddress ? `${listenAddress}:${listenPort}` : `:${listenPort}`}
            </dd>
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
            <dd>{outputs?.length ?? 0}</dd>
          </dl>
        </section>
      </ScrollArea>
    </Card>
  )
}

function OutputDetail({ entry, status }: { entry: OutputConfigEntry | null; status: OutputStatus | null }) {
  const isInmemory = entry?.type === "inmemory" || entry?.name === "inmemory"
  const inmemoryCapacity =
    (entry?.config?.["capacity"] as number | undefined) ?? undefined
  const refreshIntervalMs = useUIStore((s) => s.refreshIntervalMs)

  const eventsCountQuery = useQuery({
    queryKey: ["events", "count", "for-inmemory"],
    queryFn: ({ signal }) => api.countEvents({}, signal),
    enabled: isInmemory,
    refetchInterval: isInmemory && refreshIntervalMs > 0 ? refreshIntervalMs : false,
  })

  if (!entry) {
    return (
      <Card className="h-full min-w-0">
        <CardHeader className="min-w-0">
          <CardTitle className="text-base">Output detail</CardTitle>
          <CardDescription>Output not found.</CardDescription>
        </CardHeader>
      </Card>
    )
  }
  return (
    <Card className="flex h-full min-h-0 min-w-0 flex-col">
      <CardHeader className="min-w-0 shrink-0">
        <div className="flex min-w-0 flex-wrap items-start justify-between gap-3">
          <div className="flex min-w-0 flex-1 basis-40 items-center gap-3">
            <OutputTypeIcon type={entry.type} name={entry.name} />
            <div className="min-w-0">
              <CardTitle className="text-base leading-normal [overflow-wrap:anywhere]">{entry.name}</CardTitle>
              <CardDescription className="[overflow-wrap:anywhere]">
                type: <span className="font-mono">{entry.type}</span>
                {entry.provisioned && (
                  <span className="ml-2 text-[11px] uppercase tracking-wide">file-provisioned</span>
                )}
              </CardDescription>
            </div>
          </div>
          {status && <StatusBadge status={statusOf(status)} />}
        </div>
      </CardHeader>
      <ScrollArea className="min-h-0 min-w-0 flex-1 px-6 pb-6">
        {status && (
          <section className="flex flex-col gap-2">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              Health
            </h3>
            <dl className="grid grid-cols-2 gap-2 text-sm">
              <Stat label="Sent" value={formatNumber(status.sent_total)} tone="ok" />
              <Stat
                label="Failed"
                value={formatNumber(status.failed_total)}
                tone={status.failed_total > 0 ? "error" : "neutral"}
              />
              <Stat
                label="Dropped"
                value={formatNumber(status.dropped_total)}
                tone={status.dropped_total > 0 ? "warning" : "neutral"}
              />
              <Stat
                label="Queue"
                value={`${status.queue_depth} / ${status.queue_capacity}`}
                tone={
                  status.queue_capacity > 0 && status.queue_depth / status.queue_capacity > 0.75
                    ? "warning"
                    : "neutral"
                }
              />
              <Stat
                label="Evt/min"
                value={formatNumber(Math.round(status.events_per_minute ?? 0))}
              />
              <Stat
                label="p99 latency"
                value={status.send_latency_p99_ms == null
                  ? "Not available"
                  : formatDurationMs(status.send_latency_p99_ms)}
              />
              <Stat
                label="Circuit"
                value={status.circuit_state}
                tone={
                  status.circuit_state === "open" || status.circuit_state === "half-open"
                    ? "warning"
                    : "neutral"
                }
              />
            </dl>
            {status.last_error && (
              <div className="mt-2 flex flex-col gap-1">
                <div className="text-[10px] font-semibold uppercase tracking-wider text-status-error-foreground">
                  Last error
                </div>
                <div className="rounded-md border border-status-error/30 bg-status-error/10 px-2 py-1.5 font-mono text-xs break-all text-status-error-foreground">
                  {status.last_error}
                </div>
              </div>
            )}
          </section>
        )}

        {isInmemory && inmemoryCapacity != null && (
          <>
            {status && <Separator className="my-4" />}
            <section className="flex flex-col gap-2">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                Ring buffer
              </h3>
              {eventsCountQuery.isError ? (
                <EmptyState title="Unable to load ring-buffer usage" />
              ) : eventsCountQuery.isPending ? (
                <LoadingSkeleton lines={2} />
              ) : (
                <BufferMeter used={eventsCountQuery.data} capacity={inmemoryCapacity} />
              )}
            </section>
          </>
        )}

        <Separator className="my-4" />

        <section className="flex flex-col gap-2">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Configuration (masked)
          </h3>
          <ConfigTree data={entry.config} secretFields={entry.secret_fields} />
        </section>
      </ScrollArea>
    </Card>
  )
}

type StatTone = "ok" | "error" | "warning" | "neutral"

const TONE_CLASS: Record<StatTone, { container: string; value: string }> = {
  ok: {
    container: "border-l-2 border-l-status-ok bg-muted/30",
    value: "text-status-ok-foreground",
  },
  error: {
    container: "border-l-2 border-l-status-error bg-status-error/10",
    value: "text-status-error-foreground",
  },
  warning: {
    container: "border-l-2 border-l-status-degraded bg-status-degraded/10",
    value: "text-status-degraded-foreground",
  },
  neutral: {
    container: "border-l-2 border-l-border bg-muted/30",
    value: "text-foreground",
  },
}

function BufferMeter({ used, capacity }: { used: number; capacity: number }) {
  const pct = capacity > 0 ? Math.min(100, (used / capacity) * 100) : 0
  const tone: StatTone = pct > 90 ? "warning" : "ok"
  return (
    <div className="flex flex-col gap-1.5">
      <div className="flex flex-wrap items-baseline justify-between gap-x-2 text-sm">
        <span className="text-muted-foreground">Events stored</span>
        <span className="tabular-nums font-medium">
          {formatNumber(used)} / {formatNumber(capacity)}
        </span>
      </div>
      <div className="h-2 overflow-hidden rounded-full bg-muted">
        <div
          className={cn(
            "h-full rounded-full transition-all",
            tone === "warning" ? "bg-status-degraded" : "bg-status-ok",
          )}
          style={{ width: `${Math.max(2, pct)}%` }}
        />
      </div>
      <div className="text-xs text-muted-foreground">
        {pct.toFixed(1)}% of ring capacity.
        {pct >= 100 && " Oldest events are being overwritten."}
      </div>
    </div>
  )
}

function Stat({
  label,
  value,
  tone = "neutral",
}: {
  label: string
  value: string
  tone?: StatTone
}) {
  const t = TONE_CLASS[tone]
  return (
    <div className={cn("flex min-w-0 flex-col rounded-md px-2 py-1.5 [overflow-wrap:anywhere]", t.container)}>
      <dt className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</dt>
      <dd className={cn("tabular-nums font-medium", t.value)}>{value}</dd>
    </div>
  )
}
