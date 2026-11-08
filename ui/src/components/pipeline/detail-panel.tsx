import { useQuery } from "@tanstack/react-query"
import { AlertTriangle, ArrowRight, DatabaseZap, Pencil, Server, Trash2 } from "lucide-react"
import { useState, type ReactNode } from "react"
import { Link } from "react-router"

import falcoIcon from "@/assets/falco-icon.svg"
import { SourceChip } from "@/components/common/chips"
import { CodeBlock, InlineCode } from "@/components/common/code"
import { ConfigTree } from "@/components/common/config-tree"
import { ErrorState } from "@/components/common/error-state"
import { LoadingSkeleton } from "@/components/common/loading-skeleton"
import { Meter } from "@/components/common/meter"
import { OriginMark } from "@/components/common/origin-mark"
import { OutputTypeIcon } from "@/components/common/output-type-icon"
import { PriorityBadge } from "@/components/common/priority-badge"
import { SectionHeading } from "@/components/common/section-heading"
import { StatGrid, StatTile } from "@/components/common/stat-tile"
import { StatusBadge } from "@/components/common/status-badge"
import { TimeAgo } from "@/components/common/time-ago"
import { byAttention, needsAttention, queueTone } from "@/components/dashboard/attention"
import { OutputConfigView } from "@/components/outputs/output-config-view"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Item, ItemContent, ItemDescription, ItemGroup, ItemMedia, ItemTitle } from "@/components/ui/item"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Separator } from "@/components/ui/separator"
import { Skeleton } from "@/components/ui/skeleton"
import { useConfig } from "@/hooks/use-config"
import { useEventsCountBy, useLatestEvent } from "@/hooks/use-events"
import { useOutputTypes } from "@/hooks/use-output-writes"
import { useOutputs, usePipelineStatus } from "@/hooks/use-pipeline"
import { useRefetchInterval } from "@/hooks/use-refetch-interval"
import { api } from "@/lib/api-client"
import { errorMessage } from "@/lib/api-error"
import { formatNumber } from "@/lib/format"
import { driverOf, lastSuccessOf, PRIORITIES, statusOf, type CoreConfig, type OutputConfigEntry, type OutputStatus } from "@/lib/types"
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

function NodeHeader({ icon, title, description }: { icon: ReactNode; title: string; description: string }) {
  return (
    <CardHeader className="min-w-0 shrink-0">
      <div className="flex items-center gap-3">
        <span className="flex size-10 shrink-0 items-center justify-center rounded-md bg-brand/15 text-brand">{icon}</span>
        <div className="min-w-0">
          <CardTitle asChild className="text-base">
            <h2>{title}</h2>
          </CardTitle>
          <CardDescription>{description}</CardDescription>
        </div>
      </div>
    </CardHeader>
  )
}

/** The Falco settings that send events here, built from the ingestion listener. */
export function falcoSnippet(cfg: Pick<CoreConfig, "listen_address" | "listen_port" | "tls">): string {
  const host = cfg.listen_address && cfg.listen_address !== "0.0.0.0" && cfg.listen_address !== "::" ? cfg.listen_address : "<sidekick-host>"
  const scheme = cfg.tls?.enabled ? "https" : "http"
  return `json_output: true\nhttp_output:\n  enabled: true\n  url: ${scheme}://${host}:${cfg.listen_port}/`
}

// What Falco has sent lately, read from the event source; the listener itself is on the Configuration page.
function SourceDetail() {
  const config = useConfig()
  const latest = useLatestEvent()
  const hour = useEventsCountBy("priority", { since: "1h" })
  const sources = useEventsCountBy("source", { since: "24h" })
  const hosts = useEventsCountBy("hostname", { since: "24h" })
  const activityError = [latest, hour, sources, hosts].find((q) => q.isError)?.error
  const hourTotal = Object.values(hour.data ?? {}).reduce((a, b) => a + b, 0)
  const byPriority = PRIORITIES.filter((p) => (hour.data?.[p] ?? 0) > 0)
  const sourceNames = Object.keys(sources.data ?? {}).sort()
  const hostCount = Object.keys(hosts.data ?? {}).length

  return (
    <Card className="flex h-full min-h-0 min-w-0 flex-col">
      <NodeHeader icon={<img src={falcoIcon} alt="" aria-hidden className="size-6" />} title="Falco" description="Sends events to Sidekick over HTTP" />
      <ScrollArea className="min-h-0 min-w-0 flex-1 px-6 pb-6">
        <section className="flex flex-col gap-3" aria-label="Activity">
          <SectionHeading>Activity</SectionHeading>
          {activityError ? (
            <ErrorState title="Activity unavailable" description={errorMessage(activityError)} />
          ) : (
            <>
              <StatGrid>
                <StatTile label="Latest" value={latest.isPending ? <Skeleton className="h-5 w-16" /> : latest.data ? <TimeAgo value={latest.data.time} /> : "none yet"} />
                <StatTile label="Last hour" value={hour.isPending ? <Skeleton className="h-5 w-10" /> : formatNumber(hourTotal)} />
                <StatTile label="Hosts" value={hosts.isPending ? <Skeleton className="h-5 w-10" /> : formatNumber(hostCount)} />
              </StatGrid>
              <p className="text-xs text-muted-foreground">Hosts and sources over the last 24 hours.</p>
              {byPriority.length > 0 && (
                <ul className="flex flex-wrap gap-1.5" aria-label="Last hour by priority">
                  {byPriority.map((p) => (
                    <li key={p} className="flex items-center gap-1 text-xs tabular-nums text-muted-foreground">
                      <PriorityBadge priority={p} /> {formatNumber(hour.data?.[p] ?? 0)}
                    </li>
                  ))}
                </ul>
              )}
              {sourceNames.length > 0 && (
                <ul className="flex flex-wrap gap-1.5" aria-label="Sources in the last 24 hours">
                  {sourceNames.map((s) => (
                    <li key={s} className="min-w-0">
                      <SourceChip source={s} />
                    </li>
                  ))}
                </ul>
              )}
            </>
          )}
          <Button asChild variant="outline" size="sm" className="self-start">
            <Link to="/events?since=1h">
              Events of the last hour <ArrowRight aria-hidden />
            </Link>
          </Button>
        </section>
        <Separator className="my-4" />
        <section className="flex flex-col gap-2 text-sm">
          <SectionHeading>Connect Falco</SectionHeading>
          <p className="text-muted-foreground">
            Add this to <InlineCode>falco.yaml</InlineCode>: Falco then posts each event as JSON to <InlineCode>POST /</InlineCode>.
          </p>
          {config.data ? (
            <CodeBlock code={falcoSnippet(config.data.config)} label="the Falco settings" />
          ) : config.isError ? (
            <ErrorState title="Unable to load the listener" description={errorMessage(config.error)} />
          ) : (
            <Skeleton className="h-24 w-full" />
          )}
        </section>
      </ScrollArea>
    </Card>
  )
}

// How the pipeline delivers right now; build and settings are on the Configuration page.
function CoreDetail() {
  const statusQuery = usePipelineStatus()
  const outputsQuery = useOutputs()
  const failure = [statusQuery, outputsQuery].find((q) => q.isError)
  if (failure) {
    return <ErrorState title="Unable to load pipeline details" description={errorMessage(failure.error)} />
  }
  const statuses = statusQuery.data
  const outputs = outputsQuery.data
  if (!statuses || !outputs) {
    return <LoadingSkeleton lines={5} />
  }

  const attention = byAttention(statuses).filter(needsAttention)
  const sum = (key: "sent_total" | "failed_total" | "dropped_total") => statuses.reduce((n, s) => n + s[key], 0)
  const failed = sum("failed_total")
  const dropped = sum("dropped_total")
  const peak = statuses.reduce((m, s) => Math.max(m, s.events_per_minute), 0)

  return (
    <Card className="flex h-full min-h-0 min-w-0 flex-col">
      <NodeHeader icon={<Server className="size-5" aria-hidden />} title="Falco Sidekick" description="Receives events and fans them out to the outputs" />
      <ScrollArea className="min-h-0 min-w-0 flex-1 px-6 pb-6">
        <section className="flex flex-col gap-3" aria-label="Delivery">
          <SectionHeading>Delivery</SectionHeading>
          <StatGrid className="grid-cols-2">
            <StatTile
              label="Delivering"
              value={`${statuses.length - attention.length} of ${outputs.length}`}
              tone={attention.length > 0 ? "error" : statuses.length > 0 ? "ok" : "neutral"}
            />
            <StatTile label="Peak rate" value={`${formatNumber(Math.round(peak))}/min`} />
          </StatGrid>
          <StatGrid>
            <StatTile label="Sent" value={formatNumber(sum("sent_total"))} />
            <StatTile label="Failed" value={formatNumber(failed)} tone={failed > 0 ? "error" : "neutral"} />
            <StatTile label="Dropped" value={formatNumber(dropped)} tone={dropped > 0 ? "warning" : "neutral"} />
          </StatGrid>
          <p className="text-xs text-muted-foreground">Totals since start. The peak rate is the busiest output.</p>
        </section>
        <Separator className="my-4" />
        <section className="flex flex-col gap-2" aria-label="Needs attention">
          <SectionHeading>Needs attention</SectionHeading>
          {attention.length === 0 ? (
            <p className="text-sm text-muted-foreground">Every output is delivering.</p>
          ) : (
            <ItemGroup role="list" className="gap-1.5">
              {attention.map((s) => (
                <Item key={s.name} role="listitem" variant="outline" size="sm">
                  <ItemMedia>
                    <OutputTypeIcon driver={s.name} size="sm" />
                  </ItemMedia>
                  <ItemContent className="min-w-0">
                    <ItemTitle>{s.name}</ItemTitle>
                    {(s.last_error || s.last_warning) && <ItemDescription className="truncate">{s.last_error || s.last_warning}</ItemDescription>}
                  </ItemContent>
                  <StatusBadge status={statusOf(s)} />
                </Item>
              ))}
            </ItemGroup>
          )}
        </section>
        <Separator className="my-4" />
        <Button asChild variant="outline" size="sm">
          <Link to="/configuration">
            Version and settings <ArrowRight aria-hidden />
          </Link>
        </Button>
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
  const uiConfig = useConfig().data?.config.ui
  const servesUI = entry != null && uiConfig?.enabled === true && uiConfig.event_source === entry.name
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
        {servesUI && (
          <Item variant="outline" size="sm" className="mb-4 border-brand/30 bg-brand/5">
            <ItemMedia>
              <DatabaseZap className="size-4 text-brand" aria-hidden />
            </ItemMedia>
            <ItemContent>
              <ItemTitle>Event source</ItemTitle>
              <ItemDescription>The Events page and the dashboard read events from this output.</ItemDescription>
            </ItemContent>
          </Item>
        )}
        {status && (
          <section className="flex flex-col gap-3" aria-label="Health">
            <StatGrid>
              <StatTile label="Sent" value={formatNumber(status.sent_total)} tone="ok" />
              <StatTile label="Failed" value={formatNumber(status.failed_total)} tone={status.failed_total > 0 ? "error" : "neutral"} />
              <StatTile label="Dropped" value={formatNumber(status.dropped_total)} tone={status.dropped_total > 0 ? "warning" : "neutral"} />
            </StatGrid>
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
  const [expanded, setExpanded] = useState(false)
  const problem = problemOf(status)
  if (!problem) return null
  const error = status.last_error !== ""
  // A long error is cut to a few lines so the counters and the configuration stay in view.
  const long = problem.main.length + (problem.extra?.length ?? 0) > LONG_PROBLEM
  return (
    <Alert variant={error ? "destructive" : "default"} className={cn("mb-4", !error && "border-status-degraded/40 text-status-degraded-foreground")}>
      <AlertTriangle aria-hidden />
      <AlertTitle>{error ? "Not delivering" : "Needs a look"}</AlertTitle>
      <AlertDescription>
        <p className={cn("font-mono text-xs [overflow-wrap:anywhere]", long && !expanded && "line-clamp-4")}>{problem.main}</p>
        {problem.extra && (!long || expanded) && <p className="text-xs [overflow-wrap:anywhere]">Also: {problem.extra}</p>}
        {long && (
          <Button type="button" variant="link" size="sm" className="h-auto px-0 text-xs" onClick={() => setExpanded((v) => !v)}>
            {expanded ? "Show less" : "Show the full error"}
          </Button>
        )}
      </AlertDescription>
    </Alert>
  )
}

const LONG_PROBLEM = 240

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
