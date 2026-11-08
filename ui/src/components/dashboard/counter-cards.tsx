import { CardSkeleton } from "@/components/common/loading-skeleton"
import { StatTile } from "@/components/common/stat-tile"
import { Card, CardContent } from "@/components/ui/card"
import { useEventsCountBy } from "@/hooks/use-events"
import { errorMessage } from "@/lib/api-error"
import { formatNumber } from "@/lib/format"
import { PRIORITIES, PRIORITY_LABELS, type Priority } from "@/lib/types"

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
  const { data, isPending, isError, error } = useEventsCountBy("priority", { since: "24h" })

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
          Unable to load event counts: {errorMessage(error)}
        </CardContent>
      </Card>
    )
  }

  return (
    <dl className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-8">
      {PRIORITIES.map((p) => (
        <StatTile
          key={p}
          label={PRIORITY_LABELS[p]}
          value={formatNumber(data?.[p] ?? 0)}
          className={`rounded-xl border border-l-4 bg-card px-3 py-2.5 shadow-sm ${PRIORITY_CARD_CLASS[p]}`}
          valueClassName={`text-xl leading-tight ${PRIORITY_TEXT_CLASS[p]}`}
        />
      ))}
    </dl>
  )
}
