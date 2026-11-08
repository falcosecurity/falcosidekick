import { useSearchParams } from "react-router"

import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"
import { useEventsCountBy } from "@/hooks/use-events"
import { errorMessage } from "@/lib/api-error"
import { formatNumber } from "@/lib/format"
import { PRIORITIES, PRIORITY_LABELS, type Priority } from "@/lib/types"
import { cn } from "@/lib/utils"

import { useFiltersFromUrl } from "./event-filters"

const DOT: Record<Priority, string> = {
  emergency: "bg-priority-emergency",
  alert: "bg-priority-alert",
  critical: "bg-priority-critical",
  error: "bg-priority-error",
  warning: "bg-priority-warning",
  notice: "bg-priority-notice",
  informational: "bg-priority-info",
  debug: "bg-priority-debug",
}

/**
 * How the current results split by priority, counted with every other filter; picking priorities
 * filters the results, picking none shows them all.
 */
export function PriorityQuickFilter({ className }: { className?: string }) {
  const [params, setParams] = useSearchParams()
  const { priority: selected, ...others } = useFiltersFromUrl()
  const { data, error } = useEventsCountBy("priority", others)
  // Until the counts arrive, or when they cannot be read, every priority stays selectable and shows
  // no number: an unknown count is not zero.
  const counts = data

  const select = (values: string[]) => {
    const next = new URLSearchParams(params)
    if (values.length > 0) next.set("priority", values.join(","))
    else next.delete("priority")
    next.delete("page")
    setParams(next, { replace: true })
  }

  return (
    <div className={cn("flex flex-col gap-1.5", className)}>
      <ToggleGroup
        type="multiple"
        variant="outline"
        size="sm"
        spacing={1}
        value={selected}
        onValueChange={select}
        className="flex w-full flex-wrap"
        aria-label="Filter by priority"
      >
        {PRIORITIES.map((p) => {
          const count = counts ? (counts[p] ?? 0) : null
          return (
            <ToggleGroupItem
              key={p}
              value={p}
              disabled={count === 0 && !selected.includes(p)}
              className="gap-2 px-2.5 text-xs data-[state=on]:border-foreground/30"
              aria-label={count === null ? PRIORITY_LABELS[p] : `${PRIORITY_LABELS[p]}: ${count}`}
            >
              <span className={cn("size-2 rounded-full", DOT[p])} aria-hidden />
              {PRIORITY_LABELS[p]}
              {count !== null && <span className="tabular-nums text-muted-foreground">{formatNumber(count)}</span>}
            </ToggleGroupItem>
          )
        })}
      </ToggleGroup>
      {error && <p className="text-xs text-destructive">Counts by priority unavailable: {errorMessage(error)}</p>}
    </div>
  )
}
