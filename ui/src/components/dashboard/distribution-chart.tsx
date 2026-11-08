import { useMemo } from "react"

import { EmptyState } from "@/components/common/empty-state"
import { LoadingSkeleton } from "@/components/common/loading-skeleton"
import { Meter } from "@/components/common/meter"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { useEventsCountBy } from "@/hooks/use-events"
import { errorMessage } from "@/lib/api-error"
import { formatNumber, truncate } from "@/lib/format"
import type { GroupBy } from "@/lib/types"
import { cn } from "@/lib/utils"

const BAR_PALETTE: readonly string[] = [
  "bg-category-1",
  "bg-category-2",
  "bg-category-3",
  "bg-category-4",
  "bg-category-5",
  "bg-category-6",
  "bg-category-7",
  "bg-category-8",
  "bg-category-9",
  "bg-category-10",
] as const

const DOT_PALETTE: readonly string[] = [
  "bg-category-1/60",
  "bg-category-2/60",
  "bg-category-3/60",
  "bg-category-4/60",
  "bg-category-5/60",
  "bg-category-6/60",
  "bg-category-7/60",
  "bg-category-8/60",
  "bg-category-9/60",
  "bg-category-10/60",
] as const

interface Props {
  title: string
  groupby: Exclude<GroupBy, "priority">
  limit?: number
  className?: string
}

export function DistributionChart({ title, groupby, limit = 7, className }: Props) {
  const { data, isPending, isError, error } = useEventsCountBy(groupby, { since: "24h" })

  const { rows, max, grandTotal } = useMemo(() => {
    const entries = data
      ? Object.entries(data)
          .map(([name, count]) => ({ name, count }))
          .sort((a, b) => b.count - a.count)
      : []
    const top = entries.slice(0, limit)
    return {
      rows: top,
      max: top.reduce((acc, r) => Math.max(acc, r.count), 0) || 1,
      grandTotal: entries.reduce((acc, r) => acc + r.count, 0),
    }
  }, [data, limit])

  return (
    <Card className={className}>
      <CardHeader className="flex flex-row items-center justify-between pb-3">
        <CardTitle asChild className="text-base">
          <h2>{title}</h2>
        </CardTitle>
        {grandTotal > 0 && (
          <span className="text-xs tabular-nums text-muted-foreground">
            {formatNumber(grandTotal)} events · last 24h
          </span>
        )}
      </CardHeader>
      <CardContent>
        {isPending ? (
          <LoadingSkeleton lines={6} />
        ) : isError ? (
          <EmptyState title="Unable to load distribution" description={errorMessage(error)} />
        ) : rows.length === 0 ? (
          <EmptyState title="No data in the last 24h" />
        ) : (
          <ol className="flex flex-col gap-2">
            {rows.map((r, idx) => (
              <li key={r.name} className="group">
                <div className="flex items-baseline justify-between gap-3 text-sm">
                  <div className="flex min-w-0 items-center gap-2">
                    <span className="inline-flex w-5 shrink-0 justify-end text-2xs tabular-nums text-muted-foreground">
                      {idx + 1}
                    </span>
                    <span className={cn("size-2 shrink-0 rounded-full", DOT_PALETTE[idx % DOT_PALETTE.length])} aria-hidden />
                    <span className="truncate text-foreground" title={r.name || "(empty)"}>
                      {truncate(r.name || "(empty)", 42)}
                    </span>
                  </div>
                  <span className="shrink-0 text-xs tabular-nums text-muted-foreground">
                    {formatNumber(r.count)}
                  </span>
                </div>
                <Meter
                  decorative
                  value={Math.max(r.count, max * 0.02)}
                  max={max}
                  label={r.name}
                  className="ml-9 mt-1 h-1.5 w-auto"
                  fillClassName={cn("transition-all", BAR_PALETTE[idx % BAR_PALETTE.length])}
                />
              </li>
            ))}
          </ol>
        )}
      </CardContent>
    </Card>
  )
}
