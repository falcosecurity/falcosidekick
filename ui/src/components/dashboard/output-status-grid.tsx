import { Activity } from "lucide-react"

import { EmptyState } from "@/components/common/empty-state"
import { CardSkeleton } from "@/components/common/loading-skeleton"
import { OutputTypeIcon } from "@/components/common/output-type-icon"
import { StatusBadge } from "@/components/common/status-badge"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { usePipelineComposite, usePipelineStatus } from "@/hooks/use-pipeline"
import { formatNumber } from "@/lib/format"
import { statusOf } from "@/lib/types"
import { cn } from "@/lib/utils"

export function OutputStatusGrid() {
  const { data: statusList, isPending, isError } = usePipelineStatus()
  const { data: composite } = usePipelineComposite()

  const items = Array.isArray(statusList) ? statusList : []
  const typeByName = new Map<string, string>()
  if (composite) {
    for (const entry of composite.outputs) {
      typeByName.set(entry.name, entry.type)
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Output status</CardTitle>
      </CardHeader>
      <CardContent className="@container">
        {isPending ? (
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {Array.from({ length: 3 }).map((_, i) => (
              <CardSkeleton key={i} />
            ))}
          </div>
        ) : isError ? (
          <EmptyState title="Unable to load output status" />
        ) : items.length === 0 ? (
          <EmptyState
            icon={<Activity className="size-8" aria-hidden />}
            title="No outputs configured"
            description="Add an output to your falcosidekick outputs config to see it here."
          />
        ) : (
          <div className="flex flex-col gap-2">
            {items.map((s) => {
              const type = typeByName.get(s.name)
              const queuePct =
                s.queue_capacity > 0 ? (s.queue_depth / s.queue_capacity) * 100 : 0
              return (
                <div
                  key={s.name}
                  className="grid min-w-0 grid-cols-1 items-center gap-4 rounded-lg border bg-card px-4 py-3 transition-colors hover:border-foreground/20 @min-[20rem]:grid-cols-[minmax(0,1fr)_auto] @min-[48rem]:grid-cols-[minmax(0,1fr)_minmax(0,2fr)_auto]"
                >
                  <div className="flex min-w-0 items-center gap-3">
                    <OutputTypeIcon type={type} name={s.name} />
                    <div className="min-w-0">
                      <div className="text-sm font-semibold [overflow-wrap:anywhere]">{s.name}</div>
                      <div className="mt-0.5 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted-foreground">
                        {type && (
                          <>
                            <span className="font-mono [overflow-wrap:anywhere]">{type}</span>
                            <span aria-hidden>·</span>
                          </>
                        )}
                        <span className="[overflow-wrap:anywhere]">
                          {formatNumber(Math.round(s.events_per_minute ?? 0))} evt/min
                        </span>
                      </div>
                    </div>
                  </div>
                  <div className="flex flex-col items-start gap-1 @min-[20rem]:col-start-2 @min-[20rem]:row-start-1 @min-[20rem]:items-end @min-[48rem]:col-start-3">
                    <StatusBadge status={statusOf(s)} />
                    {s.circuit_state && s.circuit_state !== "closed" && (
                      <span className="text-[10px] text-status-degraded-foreground">
                        circuit: {s.circuit_state}
                      </span>
                    )}
                  </div>
                  <dl className="grid min-w-0 grid-cols-2 gap-3 @min-[20rem]:col-span-full @min-[24rem]:grid-cols-4 @min-[48rem]:col-span-1 @min-[48rem]:col-start-2 @min-[48rem]:row-start-1">
                    <Metric label="Sent" value={formatNumber(s.sent_total)} tone="ok" />
                    <Metric
                      label="Failed"
                      value={formatNumber(s.failed_total)}
                      tone={s.failed_total > 0 ? "error" : "neutral"}
                    />
                    <Metric
                      label="Dropped"
                      value={formatNumber(s.dropped_total)}
                      tone={s.dropped_total > 0 ? "warning" : "neutral"}
                    />
                    <QueueMetric
                      depth={s.queue_depth}
                      capacity={s.queue_capacity}
                      pct={queuePct}
                    />
                  </dl>
                  {s.last_error && (
                    <div
                      className="col-span-full min-w-0 rounded-md border border-status-error/30 bg-status-error/10 px-2 py-1 text-xs text-status-error-foreground [overflow-wrap:anywhere]"
                    >
                      {s.last_error}
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        )}
      </CardContent>
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

function Metric({
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
    <div className="flex min-w-0 flex-col">
      <dt className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</dt>
      <dd className={cn("break-all text-sm tabular-nums font-semibold", t.value)}>{value}</dd>
    </div>
  )
}

function QueueMetric({
  depth,
  capacity,
  pct,
}: {
  depth: number
  capacity: number
  pct: number
}) {
  const tone: StatTone = pct > 75 ? "warning" : "neutral"
  const t = TONE_CLASS[tone]
  const barClass = pct > 75 ? "bg-status-degraded" : "bg-brand/70"
  return (
    <div className="flex min-w-0 flex-col gap-1">
      <dt className="text-[10px] uppercase tracking-wider text-muted-foreground">Queue</dt>
      <dd className={cn("flex flex-col gap-1 break-all text-sm tabular-nums font-semibold", t.value)}>
        {depth}/{capacity}
        <div className="h-1 overflow-hidden rounded-full bg-muted" aria-hidden>
          <div
            className={cn("h-full rounded-full", barClass)}
            style={{ width: `${Math.max(0, Math.min(100, pct))}%` }}
          />
        </div>
      </dd>
    </div>
  )
}
