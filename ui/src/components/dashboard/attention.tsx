import { AlertTriangle, ArrowRight, CircleCheck, CircleDashed, Siren } from "lucide-react"
import { useMemo, type ReactNode } from "react"
import { Link } from "react-router"

import { OutputTypeIcon } from "@/components/common/output-type-icon"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Skeleton } from "@/components/ui/skeleton"
import { useEventsCountBy } from "@/hooks/use-events"
import { usePipelineStatus } from "@/hooks/use-pipeline"
import { errorMessage } from "@/lib/api-error"
import { formatNumber } from "@/lib/format"
import type { OutputStatus } from "@/lib/types"
import { cn } from "@/lib/utils"

import { CRITICAL_PRIORITIES } from "./severity"

export const QUEUE_WARNING_PERCENT = 75

const UNHEALTHY = new Set(["error", "failed", "degraded"])

export function queueTone(depth: number, capacity: number): "warning" | "neutral" {
  return capacity > 0 && (depth / capacity) * 100 > QUEUE_WARNING_PERCENT ? "warning" : "neutral"
}

export function queueFilling(s: OutputStatus): boolean {
  return queueTone(s.queue_depth, s.queue_capacity) === "warning"
}

/** An output that is not delivering, or whose queue is close to full. */
export function needsAttention(s: OutputStatus): boolean {
  return UNHEALTHY.has(s.status) || queueFilling(s)
}

/** Outputs that need attention first, then by name. */
export function byAttention(list: readonly OutputStatus[]): OutputStatus[] {
  return [...list].sort((a, b) => Number(needsAttention(b)) - Number(needsAttention(a)) || a.name.localeCompare(b.name))
}

interface AttentionItem {
  key: string
  media: ReactNode
  title: ReactNode
  detail: string
  to: string
}

const CRITICAL_LINK = `/events?priority=${CRITICAL_PRIORITIES.join(",")}&since=1h`

function useAttentionItems() {
  const status = usePipelineStatus()
  const critical = useEventsCountBy("priority", { since: "1h" })
  const items = useMemo<AttentionItem[]>(() => {
    const result: AttentionItem[] = []
    const criticalCount = CRITICAL_PRIORITIES.reduce((sum, p) => sum + (critical.data?.[p] ?? 0), 0)
    if (criticalCount > 0) {
      result.push({
        key: "critical",
        media: (
          <span className="flex size-8 items-center justify-center rounded-md bg-priority-alert/15 text-priority-alert-foreground">
            <Siren className="size-4" aria-hidden />
          </span>
        ),
        title: `${formatNumber(criticalCount)} critical or worse ${criticalCount === 1 ? "event" : "events"} in the last hour`,
        detail: "Emergency, alert and critical priorities",
        to: CRITICAL_LINK,
      })
    }
    for (const s of byAttention(status.data ?? []).filter(needsAttention)) {
      const what = UNHEALTHY.has(s.status) ? (s.status === "degraded" ? "is degraded" : "is not delivering") : "queue is filling up"
      result.push({
        key: `output:${s.name}`,
        media: <OutputTypeIcon driver={s.name} size="sm" />,
        title: (
          <>
            <span className="font-semibold">{s.name}</span> {what}
          </>
        ),
        detail: [s.last_error || s.last_warning, `${formatNumber(s.queue_depth)} of ${formatNumber(s.queue_capacity)} queued`]
          .filter(Boolean)
          .join(" · "),
        to: "/pipeline",
      })
    }
    return result
  }, [status.data, critical.data])
  return { items, isPending: status.isPending || critical.isPending, error: status.error ?? critical.error }
}

/** What an operator should look at now; it turns red while anything is listed. */
export function AttentionCard({ className }: { className?: string }) {
  const { items, isPending, error } = useAttentionItems()
  const known = !isPending && !error
  const alerting = known && items.length > 0
  return (
    <Card size="sm" className={cn(alerting && "border-status-error/40 bg-status-error/[0.04] dark:bg-status-error/[0.07]", className)}>
      <CardHeader className="px-5">
        <CardTitle asChild className="flex items-center gap-2 text-base">
          <h2>
            {alerting ? (
              <AlertTriangle className="size-4 text-status-error-foreground" aria-hidden />
            ) : known ? (
              <CircleCheck className="size-4 text-status-ok-foreground" aria-hidden />
            ) : (
              <CircleDashed className="size-4 text-muted-foreground" aria-hidden />
            )}
            Needs attention
          </h2>
        </CardTitle>
        <CardDescription>Outputs that do not deliver and critical events of the last hour.</CardDescription>
        {alerting && (
          <CardAction>
            <Badge variant="destructive" className="tabular-nums">
              {items.length}
            </Badge>
          </CardAction>
        )}
      </CardHeader>
      <CardContent className="flex-1 px-5">
        {isPending ? (
          <div className="flex flex-col gap-2">
            <Skeleton className="h-14 w-full" />
            <Skeleton className="h-14 w-full" />
          </div>
        ) : error ? (
          <Alert variant="destructive">
            <AlertTriangle aria-hidden />
            <AlertTitle>Unable to check what needs attention</AlertTitle>
            <AlertDescription>{errorMessage(error)}</AlertDescription>
          </Alert>
        ) : !alerting ? (
          <Empty className="h-full gap-3 border border-dashed p-6">
            <EmptyHeader>
              <EmptyMedia variant="icon">
                <CircleCheck className="text-status-ok-foreground" />
              </EmptyMedia>
              <EmptyTitle>All clear</EmptyTitle>
              <EmptyDescription>Every output is delivering and no critical event arrived in the last hour.</EmptyDescription>
            </EmptyHeader>
          </Empty>
        ) : (
          <ScrollArea className="max-h-80">
          <ul className="flex flex-col gap-2 pr-1">
            {items.map((item) => (
              <li key={item.key}>
                <Link
                  to={item.to}
                  className="group flex items-center gap-3 rounded-lg border bg-card px-3 py-2.5 text-sm transition-colors hover:border-foreground/20 hover:bg-accent/40 focus-visible:outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50"
                >
                  {item.media}
                  <span className="flex min-w-0 flex-1 flex-col gap-0.5">
                    <span className="[overflow-wrap:anywhere]">{item.title}</span>
                    <span className="truncate text-xs text-muted-foreground" title={item.detail}>
                      {item.detail}
                    </span>
                  </span>
                  <ArrowRight className="size-4 shrink-0 text-muted-foreground transition-transform group-hover:translate-x-0.5" aria-hidden />
                </Link>
              </li>
            ))}
          </ul>
          </ScrollArea>
        )}
      </CardContent>
    </Card>
  )
}
