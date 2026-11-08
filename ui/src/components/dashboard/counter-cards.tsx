import { CardSkeleton } from "@/components/common/loading-skeleton"
import { Card, CardContent } from "@/components/ui/card"
import { useEventsCountBy } from "@/hooks/use-events"
import { formatNumber } from "@/lib/format"
import { PRIORITIES, PRIORITY_LABELS, type Priority } from "@/lib/types"
import { cn } from "@/lib/utils"

const PRIORITY_CARD_CLASS: Record<Priority, string> = {
  emergency: "border-l-priority-emergency",
  alert: "border-l-priority-alert",
  critical: "border-l-priority-critical",
  error: "border-l-priority-error",
  warning: "border-l-priority-warning",
  notice: "border-l-priority-notice",
  informational: "border-l-priority-info",
  debug: "border-l-priority-debug",
}

const PRIORITY_TEXT_CLASS: Record<Priority, string> = {
  emergency: "text-priority-emergency-foreground",
  alert: "text-priority-alert-foreground",
  critical: "text-priority-critical-foreground",
  error: "text-priority-error-foreground",
  warning: "text-priority-warning-foreground",
  notice: "text-priority-notice-foreground",
  informational: "text-priority-info-foreground",
  debug: "text-priority-debug-foreground",
}

export function CounterCards() {
  const { data, isPending, isError } = useEventsCountBy("priority", { since: "24h" })

  if (isPending) {
    return (
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-8">
        {PRIORITIES.map((p) => (
          <CardSkeleton key={p} />
        ))}
      </div>
    )
  }

  if (isError) {
    return (
      <Card>
        <CardContent className="py-6 text-sm text-muted-foreground">
          Unable to load event counts.
        </CardContent>
      </Card>
    )
  }

  return (
    <div className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-8">
      {PRIORITIES.map((p) => {
        const count = data?.[p] ?? 0
        return (
          <Card key={p} className={cn("border-l-4", PRIORITY_CARD_CLASS[p])}>
            <CardContent className="flex flex-col gap-0.5 px-3 py-2.5">
              <span className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
                {PRIORITY_LABELS[p]}
              </span>
              <span className={cn("text-xl font-semibold tabular-nums leading-tight", PRIORITY_TEXT_CLASS[p])}>
                {formatNumber(count)}
              </span>
            </CardContent>
          </Card>
        )
      })}
    </div>
  )
}
