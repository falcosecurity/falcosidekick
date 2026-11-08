import { AlertTriangle } from "lucide-react"
import { useMemo, useState } from "react"
import { Area, AreaChart, CartesianGrid, XAxis, YAxis } from "recharts"

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { ChartContainer, ChartTooltip, ChartTooltipContent, type ChartConfig } from "@/components/ui/chart"
import { Empty, EmptyDescription, EmptyHeader, EmptyTitle } from "@/components/ui/empty"
import { Skeleton } from "@/components/ui/skeleton"
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"
import { useEventsHistogram } from "@/hooks/use-events"
import { errorMessage } from "@/lib/api-error"
import { formatNumber } from "@/lib/format"
import { cn } from "@/lib/utils"

import { SEVERITY_TIERS, tierRows } from "./severity"

// Enough buckets per window for a curve to read as a trend.
const WINDOWS = [
  { label: "1h", since: "1h", bucketMs: 2 * 60_000 },
  { label: "6h", since: "6h", bucketMs: 10 * 60_000 },
  { label: "24h", since: "24h", bucketMs: 30 * 60_000 },
] as const

const CONFIG = Object.fromEntries(SEVERITY_TIERS.map((t) => [t.key, { label: t.label, color: t.color }])) satisfies ChartConfig

function timeLabel(t: number): string {
  return new Date(t).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" })
}

/** Events per bucket stacked by severity tier, most severe at the bottom, with the tier totals as legend. */
export function SeverityCard({ className }: { className?: string }) {
  const [windowLabel, setWindowLabel] = useState<(typeof WINDOWS)[number]["label"]>("6h")
  const window = WINDOWS.find((w) => w.label === windowLabel)!
  const { data, isPending, error, isPlaceholderData } = useEventsHistogram({ since: window.since, bucket_ms: window.bucketMs, group_by: "priority" })
  const rows = useMemo(() => tierRows(data?.buckets ?? []), [data])
  const totals = useMemo(
    () => Object.fromEntries(SEVERITY_TIERS.map((t) => [t.key, rows.reduce((sum, r) => sum + (r[t.key] ?? 0), 0)])),
    [rows],
  )
  const all = Object.values(totals).reduce((a, b) => a + b, 0)
  // Totals are shown only from data loaded for this window: a zero must never stand for "unknown",
  // and the previous window's series, kept while the new one loads, must not take its label.
  const known = !isPending && !error && !isPlaceholderData

  return (
    <Card size="sm" className={className}>
      <CardHeader className="px-5">
        <CardTitle asChild className="text-base">
          <h2>Events by severity</h2>
        </CardTitle>
        <CardDescription>
          {known ? (
            <>
              <span className="font-medium tabular-nums text-foreground">{formatNumber(all)}</span> in the last {window.label}
            </>
          ) : (
            `Last ${window.label}`
          )}
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
          <Alert variant="destructive">
            <AlertTriangle aria-hidden />
            <AlertTitle>Unable to load events by severity</AlertTitle>
            <AlertDescription>{errorMessage(error)}</AlertDescription>
          </Alert>
        ) : all === 0 ? (
          <Empty className="h-52">
            <EmptyHeader>
              <EmptyTitle>No events</EmptyTitle>
              <EmptyDescription>Nothing arrived in the last {window.label}.</EmptyDescription>
            </EmptyHeader>
          </Empty>
        ) : (
          <ChartContainer
            config={CONFIG}
            className={cn("aspect-auto h-52 w-full transition-opacity", isPlaceholderData && "opacity-40")}
            aria-busy={isPlaceholderData || undefined}
            initialDimension={{ width: 360, height: 208 }}
          >
            <AreaChart data={rows} margin={{ top: 4, right: 4, left: 0, bottom: 0 }}>
              <defs>
                {SEVERITY_TIERS.map((tier) => (
                  <linearGradient key={tier.key} id={`severity-fill-${tier.key}`} x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor={`var(--color-${tier.key})`} stopOpacity={0.7} />
                    <stop offset="95%" stopColor={`var(--color-${tier.key})`} stopOpacity={0.15} />
                  </linearGradient>
                ))}
              </defs>
              <CartesianGrid vertical={false} />
              <XAxis dataKey="t" tickFormatter={timeLabel} tickLine={false} axisLine={false} minTickGap={32} />
              <YAxis width={32} tickLine={false} axisLine={false} allowDecimals={false} />
              <ChartTooltip cursor={false} content={<ChartTooltipContent indicator="dot" labelFormatter={(_, payload) => timeLabel(Number(payload?.[0]?.payload?.t))} />} />
              {SEVERITY_TIERS.map((tier) => (
                <Area
                  key={tier.key}
                  dataKey={tier.key}
                  type="monotone"
                  stackId="tiers"
                  stroke={`var(--color-${tier.key})`}
                  strokeWidth={1.5}
                  fill={`url(#severity-fill-${tier.key})`}
                  isAnimationActive={false}
                />
              ))}
            </AreaChart>
          </ChartContainer>
        )}
        <ul className="grid grid-cols-2 gap-x-6 gap-y-2 text-sm">
          {SEVERITY_TIERS.map((tier) => (
            <li key={tier.key} className="flex items-center gap-2">
              <span className={cn("size-2.5 shrink-0 rounded-[3px]", tier.swatch)} aria-hidden />
              <span className="text-muted-foreground">{tier.label}</span>
              <span className="ml-auto font-medium tabular-nums">{known ? formatNumber(totals[tier.key] ?? 0) : "—"}</span>
            </li>
          ))}
        </ul>
      </CardContent>
    </Card>
  )
}
