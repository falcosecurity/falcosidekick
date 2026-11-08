import { Activity, ArrowDownRight, ArrowUpRight, Minus, Send, Siren } from "lucide-react"
import type { ReactNode } from "react"

import { Badge } from "@/components/ui/badge"
import { Card, CardAction, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import { useEventsCountBy, useEventsHistogram } from "@/hooks/use-events"
import { usePipelineStatus } from "@/hooks/use-pipeline"
import { errorMessage } from "@/lib/api-error"
import { formatNumber } from "@/lib/format"
import type { Priority } from "@/lib/types"
import { cn } from "@/lib/utils"

import { needsAttention } from "./attention"
import { CRITICAL_PRIORITIES } from "./severity"

const HOUR = 3_600_000

interface Trend {
  current: number
  previous: number
}

/** Last hour against the hour before, from one two-bucket histogram. */
function useHourTrend(only?: readonly Priority[]) {
  const query = useEventsHistogram({ since: "2h", bucket_ms: HOUR, group_by: "priority" })
  const buckets = query.data?.buckets ?? []
  const count = (i: number) => {
    const b = buckets[i]
    if (!b) return 0
    return only ? only.reduce((sum, p) => sum + (b.by?.[p] ?? 0), 0) : b.count
  }
  const trend: Trend | null = buckets.length >= 2 ? { current: count(buckets.length - 1), previous: count(buckets.length - 2) } : null
  return { trend, query }
}

/** Direction and size of the change; "up" is bad for these metrics, so it carries the alert tone. */
function TrendBadge({ trend }: { trend: Trend }) {
  const { current, previous } = trend
  if (previous === 0 && current === 0) return null
  const delta = previous === 0 ? null : Math.round(((current - previous) / previous) * 100)
  const up = current > previous
  const flat = current === previous
  const Icon = flat ? Minus : up ? ArrowUpRight : ArrowDownRight
  return (
    <Badge variant="outline" className={cn("gap-1 font-normal tabular-nums", up && "border-priority-alert/30 text-priority-alert-foreground")}>
      <Icon aria-hidden />
      {delta === null ? "new" : `${delta > 0 ? "+" : ""}${delta}%`}
      <span className="sr-only">compared with the hour before</span>
    </Badge>
  )
}

function Kpi({
  label,
  value,
  icon,
  action,
  footer,
  tone,
  query,
}: {
  label: string
  value: string
  icon: ReactNode
  action?: ReactNode
  footer: ReactNode
  tone?: "alert" | "ok"
  /** The figure is shown only once its data loaded: a zero must never stand for "unknown". */
  query: { isPending: boolean; error: unknown }
}) {
  const ready = !query.isPending && !query.error
  return (
    <Card className="@container/card min-w-0 gap-3 py-5 shadow-xs">
      <CardHeader className="px-5">
        <CardDescription className="flex min-h-[2lh] min-w-0 items-start gap-1.5">
          <span className="mt-0.5 shrink-0">{icon}</span>
          <span className="line-clamp-2">{label}</span>
        </CardDescription>
        {query.isPending ? (
          <Skeleton className="h-8 w-20" />
        ) : (
          <CardTitle
            className={cn(
              "text-2xl font-semibold tabular-nums tracking-tight whitespace-nowrap @[250px]/card:text-3xl",
              ready && tone === "alert" && "text-priority-alert-foreground",
              ready && tone === "ok" && "text-status-ok-foreground",
              !ready && "text-muted-foreground",
            )}
          >
            {ready ? value : "—"}
          </CardTitle>
        )}
        {ready && action && <CardAction>{action}</CardAction>}
      </CardHeader>
      <CardFooter className="px-5 text-xs text-muted-foreground">
        {query.isPending ? <Skeleton className="h-3 w-32" /> : query.error ? `Unavailable: ${errorMessage(query.error)}` : footer}
      </CardFooter>
    </Card>
  )
}

export function KpiCards() {
  const all = useHourTrend()
  const critical = useHourTrend(CRITICAL_PRIORITIES)
  const day = useEventsCountBy("priority", { since: "24h" })
  const status = usePipelineStatus()
  const outputs = status.data ?? []
  const unhealthy = outputs.filter(needsAttention)
  const perMinute = outputs.reduce((sum, s) => Math.max(sum, s.events_per_minute), 0)
  const dayTotal = Object.values(day.data ?? {}).reduce((a, b) => a + b, 0)

  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 [&>*]:min-w-0">
      <Kpi
        label="Events, last hour"
        icon={<Activity className="size-3.5" aria-hidden />}
        value={formatNumber(all.trend?.current ?? 0)}
        action={all.trend && <TrendBadge trend={all.trend} />}
        footer={`${formatNumber(all.trend?.previous ?? 0)} the hour before`}
        query={all.query}
      />
      <Kpi
        label="Critical or worse, last hour"
        icon={<Siren className="size-3.5" aria-hidden />}
        value={formatNumber(critical.trend?.current ?? 0)}
        tone={(critical.trend?.current ?? 0) > 0 ? "alert" : undefined}
        action={critical.trend && <TrendBadge trend={critical.trend} />}
        footer="Emergency, alert and critical"
        query={critical.query}
      />
      <Kpi
        label="Outputs delivering"
        icon={<Send className="size-3.5" aria-hidden />}
        value={`${outputs.length - unhealthy.length} of ${outputs.length}`}
        tone={outputs.length > 0 && unhealthy.length === 0 ? "ok" : unhealthy.length > 0 ? "alert" : undefined}
        action={
          unhealthy.length > 0 ? (
            <Badge variant="outline" className="border-status-error/30 font-normal text-status-error-foreground">
              {unhealthy.length} need attention
            </Badge>
          ) : undefined
        }
        footer={outputs.length === 0 ? "No outputs configured" : `Up to ${formatNumber(perMinute)} events per minute per output`}
        query={status}
      />
      <Kpi
        label="Events, last 24 hours"
        icon={<Activity className="size-3.5" aria-hidden />}
        value={formatNumber(dayTotal)}
        footer="Kept by the event store the UI reads"
        query={day}
      />
    </div>
  )
}
