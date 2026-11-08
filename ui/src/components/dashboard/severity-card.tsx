import { useMemo, useState } from "react"
import { Bar, BarChart, CartesianGrid, XAxis, YAxis } from "recharts"

import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { ChartContainer, ChartTooltip, ChartTooltipContent, type ChartConfig } from "@/components/ui/chart"
import { Skeleton } from "@/components/ui/skeleton"
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"
import { useEventsHistogram } from "@/hooks/use-events"
import { errorMessage } from "@/lib/api-error"
import { formatNumber } from "@/lib/format"
import { cn } from "@/lib/utils"

import { SEVERITY_TIERS, tierRows } from "./severity"

const WINDOWS = [
  { label: "1h", since: "1h", bucketMs: 5 * 60_000 },
  { label: "6h", since: "6h", bucketMs: 30 * 60_000 },
  { label: "24h", since: "24h", bucketMs: 2 * 3_600_000 },
] as const

const CONFIG = Object.fromEntries(SEVERITY_TIERS.map((t) => [t.key, { label: t.label, color: t.color }])) satisfies ChartConfig

function timeLabel(t: number): string {
  return new Date(t).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" })
}

/** Events per bucket stacked by severity tier, most severe at the bottom, with the tier totals as legend. */
export function SeverityCard({ className }: { className?: string }) {
  const [windowLabel, setWindowLabel] = useState<(typeof WINDOWS)[number]["label"]>("6h")
  const window = WINDOWS.find((w) => w.label === windowLabel)!
  const { data, isPending, error } = useEventsHistogram({ since: window.since, bucket_ms: window.bucketMs, group_by: "priority" })
  const rows = useMemo(() => tierRows(data?.buckets ?? []), [data])
  const totals = useMemo(
    () => Object.fromEntries(SEVERITY_TIERS.map((t) => [t.key, rows.reduce((sum, r) => sum + (r[t.key] ?? 0), 0)])),
    [rows],
  )
  const all = Object.values(totals).reduce((a, b) => a + b, 0)

  return (
    <Card className={cn("gap-4 py-5 shadow-xs", className)}>
      <CardHeader className="px-5">
        <CardTitle className="text-base">Events by severity</CardTitle>
        <CardDescription>
          <span className="font-medium tabular-nums text-foreground">{formatNumber(all)}</span> in the last {window.label}
        </CardDescription>
        <CardAction>
          <ToggleGroup type="single" variant="outline" size="sm" value={windowLabel} onValueChange={(v) => v && setWindowLabel(v as typeof windowLabel)} aria-label="Time window">
            {WINDOWS.map((w) => (
              <ToggleGroupItem key={w.label} value={w.label} className="px-2.5 text-xs">
                {w.label}
              </ToggleGroupItem>
            ))}
          </ToggleGroup>
        </CardAction>
      </CardHeader>
      <CardContent className="flex flex-1 flex-col gap-4 px-5">
        {isPending ? (
          <Skeleton className="h-52 w-full" />
        ) : error ? (
          <p className="text-sm text-destructive">{errorMessage(error)}</p>
        ) : all === 0 ? (
          <p className="flex h-52 items-center justify-center text-sm text-muted-foreground">No events in the last {window.label}.</p>
        ) : (
          <ChartContainer config={CONFIG} className="aspect-auto h-52 w-full" initialDimension={{ width: 360, height: 208 }}>
            <BarChart data={rows} margin={{ top: 4, right: 0, left: 0, bottom: 0 }} barCategoryGap={2}>
              <CartesianGrid vertical={false} />
              <XAxis dataKey="t" tickFormatter={timeLabel} tickLine={false} axisLine={false} minTickGap={32} />
              <YAxis width={32} tickLine={false} axisLine={false} allowDecimals={false} />
              <ChartTooltip cursor={{ fillOpacity: 0.4 }} content={<ChartTooltipContent labelFormatter={(_, payload) => timeLabel(Number(payload?.[0]?.payload?.t))} />} />
              {SEVERITY_TIERS.map((tier, i) => (
                <Bar
                  key={tier.key}
                  dataKey={tier.key}
                  stackId="tiers"
                  fill={`var(--color-${tier.key})`}
                  radius={i === SEVERITY_TIERS.length - 1 ? [3, 3, 0, 0] : 0}
                  isAnimationActive={false}
                />
              ))}
            </BarChart>
          </ChartContainer>
        )}
        <ul className="grid grid-cols-2 gap-x-6 gap-y-2 text-sm">
          {SEVERITY_TIERS.map((tier) => (
            <li key={tier.key} className="flex items-center gap-2">
              <span className={cn("size-2.5 shrink-0 rounded-[3px]", tier.swatch)} aria-hidden />
              <span className="truncate text-muted-foreground">{tier.label}</span>
              <span className="ml-auto font-medium tabular-nums">{formatNumber(totals[tier.key] ?? 0)}</span>
            </li>
          ))}
        </ul>
      </CardContent>
    </Card>
  )
}
