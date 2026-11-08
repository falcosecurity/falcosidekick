import { Activity } from "lucide-react"

import { EmptyState } from "@/components/common/empty-state"
import { CardSkeleton } from "@/components/common/loading-skeleton"
import { Meter } from "@/components/common/meter"
import { OutputTypeIcon } from "@/components/common/output-type-icon"
import { StatTile } from "@/components/common/stat-tile"
import { StatusBadge } from "@/components/common/status-badge"
import { TimeAgo } from "@/components/common/time-ago"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { usePipelineStatus } from "@/hooks/use-pipeline"
import { errorMessage } from "@/lib/api-error"
import { formatNumber } from "@/lib/format"
import { driverOf, lastSuccessOf, type OutputStatus } from "@/lib/types"

export const QUEUE_WARNING_PERCENT = 75

export function queueTone(depth: number, capacity: number): "warning" | "neutral" {
  return capacity > 0 && (depth / capacity) * 100 > QUEUE_WARNING_PERCENT ? "warning" : "neutral"
}

export function OutputStatusGrid() {
  const { data: statusList, isPending, isError, error } = usePipelineStatus()
  const items = statusList ?? []

  return (
    <Card>
      <CardHeader>
        <CardTitle asChild className="text-base">
          <h2>Output status</h2>
        </CardTitle>
      </CardHeader>
      <CardContent className="@container">
        {isPending ? (
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {Array.from({ length: 3 }).map((_, i) => (
              <CardSkeleton key={i} />
            ))}
          </div>
        ) : isError ? (
          <EmptyState title="Unable to load output status" description={errorMessage(error)} />
        ) : items.length === 0 ? (
          <EmptyState
            icon={<Activity className="size-8" aria-hidden />}
            title="No outputs configured"
            description="Add an output to your falcosidekick outputs config to see it here."
          />
        ) : (
          <ul className="flex flex-col gap-2">
            {items.map((s) => (
              <OutputRow key={s.name} status={s} />
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  )
}

function OutputRow({ status: s }: { status: OutputStatus }) {
  const lastSuccess = lastSuccessOf(s)
  return (
    <li className="grid min-w-0 grid-cols-1 items-center gap-4 rounded-lg border bg-card px-4 py-3 transition-colors hover:border-foreground/20 @min-[20rem]:grid-cols-[minmax(0,1fr)_auto] @min-[48rem]:grid-cols-[minmax(0,1fr)_minmax(0,2fr)_auto]">
      <div className="flex min-w-0 items-center gap-3">
        <OutputTypeIcon driver={driverOf(s)} />
        <div className="min-w-0">
          <h3 className="text-sm font-semibold [overflow-wrap:anywhere]">{s.name}</h3>
          <div className="mt-0.5 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted-foreground">
            <span>{formatNumber(Math.round(s.events_per_minute))} evt/min</span>
            <span aria-hidden>·</span>
            <span>
              last success {lastSuccess ? <TimeAgo value={lastSuccess} /> : "never"}
            </span>
          </div>
        </div>
      </div>
      <div className="flex flex-col items-start gap-1 @min-[20rem]:col-start-2 @min-[20rem]:row-start-1 @min-[20rem]:items-end @min-[48rem]:col-start-3">
        <StatusBadge status={s.status} />
        {s.circuit_state && s.circuit_state !== "closed" && (
          <span className="text-2xs text-status-degraded-foreground">circuit: {s.circuit_state}</span>
        )}
      </div>
      <dl className="grid min-w-0 grid-cols-2 gap-2 @min-[20rem]:col-span-full @min-[24rem]:grid-cols-4 @min-[48rem]:col-span-1 @min-[48rem]:col-start-2 @min-[48rem]:row-start-1">
        <StatTile label="Sent" value={formatNumber(s.sent_total)} tone="ok" />
        <StatTile label="Failed" value={formatNumber(s.failed_total)} tone={s.failed_total > 0 ? "error" : "neutral"} />
        <StatTile label="Dropped" value={formatNumber(s.dropped_total)} tone={s.dropped_total > 0 ? "warning" : "neutral"} />
        <StatTile label="Queue" value={`${s.queue_depth}/${s.queue_capacity}`} tone={queueTone(s.queue_depth, s.queue_capacity)}>
          <Meter
            value={s.queue_depth}
            max={s.queue_capacity}
            label={`Queue ${s.name}`}
            tone={queueTone(s.queue_depth, s.queue_capacity) === "warning" ? "warning" : "brand"}
            className="mt-1"
          />
        </StatTile>
      </dl>
      {s.last_error && (
        <div className="col-span-full min-w-0 rounded-md border border-status-error/30 bg-status-error/10 px-2 py-1 text-xs text-status-error-foreground [overflow-wrap:anywhere]">
          {s.last_error}
        </div>
      )}
      {s.last_warning && (
        <div className="col-span-full min-w-0 rounded-md border border-status-degraded/30 bg-status-degraded/10 px-2 py-1 text-xs text-status-degraded-foreground [overflow-wrap:anywhere]">
          {s.last_warning}
        </div>
      )}
    </li>
  )
}
