import { useMemo } from "react"
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts"

import { EmptyState } from "@/components/common/empty-state"
import { LoadingSkeleton } from "@/components/common/loading-skeleton"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { useEventsCountBy } from "@/hooks/use-events"
import { formatNumber } from "@/lib/format"

const SLICE_PALETTE: readonly string[] = [
  "var(--category-1)",
  "var(--category-2)",
  "var(--category-3)",
  "var(--category-4)",
  "var(--category-5)",
  "var(--category-6)",
  "var(--category-7)",
  "var(--category-8)",
] as const

interface SourcePieChartProps {
  className?: string
  groupby?: "source" | "priority" | "rule"
  title?: string
}

export function SourcePieChart({
  className,
  groupby = "source",
  title = "Sources",
}: SourcePieChartProps) {
  const { data, isPending, isError } = useEventsCountBy(groupby, { since: "24h" })

  const { slices, total } = useMemo(() => {
    const entries = data
      ? Object.entries(data)
          .map(([name, count]) => ({ name, value: count }))
          .sort((a, b) => b.value - a.value)
      : []
    return {
      slices: entries,
      total: entries.reduce((acc, r) => acc + r.value, 0),
    }
  }, [data])

  return (
    <Card className={className}>
      <CardHeader className="flex flex-row items-center justify-between pb-3">
        <CardTitle className="text-base">{title}</CardTitle>
        {total > 0 && (
          <span className="text-xs tabular-nums text-muted-foreground">
            {formatNumber(total)} · last 24h
          </span>
        )}
      </CardHeader>
      <CardContent>
        {isPending ? (
          <LoadingSkeleton lines={5} />
        ) : isError ? (
          <EmptyState title="Unable to load distribution" />
        ) : total === 0 ? (
          <EmptyState title="No data in the last 24h" />
        ) : (
          <div className="grid grid-cols-[1fr_1fr] items-center gap-4">
            <div className="h-44">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={slices}
                    dataKey="value"
                    nameKey="name"
                    innerRadius={45}
                    outerRadius={75}
                    stroke="var(--background)"
                    strokeWidth={2}
                    paddingAngle={1}
                  >
                    {slices.map((_, i) => (
                      <Cell
                        key={i}
                        fill={SLICE_PALETTE[i % SLICE_PALETTE.length]}
                      />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      background: "var(--popover)",
                      borderColor: "var(--border)",
                      borderRadius: "var(--radius-md)",
                      fontSize: "12px",
                    }}
                    itemStyle={{ color: "var(--foreground)" }}
                    formatter={(value, name) => {
                      const v = typeof value === "number" ? value : Number(value ?? 0)
                      return [
                        `${formatNumber(v)} (${((v / total) * 100).toFixed(1)}%)`,
                        String(name),
                      ]
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <ul className="flex flex-col gap-1.5 text-xs">
              {slices.map((s, i) => {
                const pct = (s.value / total) * 100
                return (
                  <li key={s.name} className="flex items-center gap-2">
                    <span
                      className="size-2.5 shrink-0 rounded-sm"
                      style={{ background: SLICE_PALETTE[i % SLICE_PALETTE.length] }}
                      aria-hidden
                    />
                    <span className="min-w-0 flex-1 truncate text-foreground">{s.name}</span>
                    <span className="tabular-nums text-muted-foreground">
                      {formatNumber(s.value)}
                    </span>
                    <span className="w-10 shrink-0 text-right tabular-nums text-muted-foreground">
                      {pct.toFixed(1)}%
                    </span>
                  </li>
                )
              })}
            </ul>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
