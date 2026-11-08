import { useState } from "react"
import { Link } from "react-router"

import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"
import { useEventsCountBy } from "@/hooks/use-events"
import { errorMessage } from "@/lib/api-error"
import { formatNumber } from "@/lib/format"
import type { GroupBy } from "@/lib/types"

const DIMENSIONS: { key: GroupBy; label: string }[] = [
  { key: "rule", label: "Rules" },
  { key: "hostname", label: "Hosts" },
  { key: "source", label: "Sources" },
]

const LIMIT = 8

/** The busiest rules, hosts or sources of the last 24 hours, largest first; each row filters the events. */
export function TopCard({ className }: { className?: string }) {
  const [groupBy, setGroupBy] = useState<GroupBy>("rule")
  const { data, isPending, error } = useEventsCountBy(groupBy, { since: "24h" })
  const ranked = Object.entries(data ?? {})
    .sort((a, b) => b[1] - a[1])
    .slice(0, LIMIT)
  const max = ranked[0]?.[1] ?? 1
  return (
    <Card size="sm" className={className}>
      <CardHeader className="px-5">
        <CardTitle asChild className="text-base">
          <h2>Top {DIMENSIONS.find((d) => d.key === groupBy)!.label.toLowerCase()}</h2>
        </CardTitle>
        <CardDescription>Last 24 hours</CardDescription>
        <CardAction>
          <ToggleGroup type="single" variant="outline" size="sm" value={groupBy} onValueChange={(v) => v && setGroupBy(v as GroupBy)} aria-label="Group by">
            {DIMENSIONS.map((d) => (
              <ToggleGroupItem key={d.key} value={d.key} className="px-2.5 text-xs">
                {d.label}
              </ToggleGroupItem>
            ))}
          </ToggleGroup>
        </CardAction>
      </CardHeader>
      <CardContent className="px-3">
        {isPending ? (
          <div className="flex flex-col gap-2 px-2">
            {Array.from({ length: 5 }, (_, i) => (
              <Skeleton key={i} className="h-8 w-full" />
            ))}
          </div>
        ) : error ? (
          <p className="px-2 text-sm text-destructive">{errorMessage(error)}</p>
        ) : ranked.length === 0 ? (
          <p className="px-2 text-sm text-muted-foreground">No events in the last 24 hours.</p>
        ) : (
          <ol className="flex flex-col">
            {ranked.map(([name, count]) => (
              <li key={name}>
                <Link
                  to={`/events?${groupBy}=${encodeURIComponent(name)}&since=24h`}
                  className="group grid grid-cols-[1fr_auto] items-center gap-x-3 gap-y-1.5 rounded-md px-2 py-2 text-sm hover:bg-accent/50 focus-visible:outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50"
                >
                  <span className="truncate" title={name}>
                    {name}
                  </span>
                  <span className="tabular-nums text-muted-foreground">{formatNumber(count)}</span>
                  <span className="col-span-2 h-1.5 overflow-hidden rounded-full bg-muted" aria-hidden>
                    <span className="block h-full rounded-full bg-chart-1/80 group-hover:bg-chart-1" style={{ width: `${(count / max) * 100}%` }} />
                  </span>
                </Link>
              </li>
            ))}
          </ol>
        )}
      </CardContent>
    </Card>
  )
}
