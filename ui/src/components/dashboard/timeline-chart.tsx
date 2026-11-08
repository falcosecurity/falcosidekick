import { useMemo, useState } from "react"
import {
  Area,
  CartesianGrid,
  ComposedChart,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts"

import { EmptyState } from "@/components/common/empty-state"
import { LoadingSkeleton } from "@/components/common/loading-skeleton"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { useEventsHistogram } from "@/hooks/use-events"
import { formatNumber } from "@/lib/format"

type Window = "1h" | "6h" | "24h"
type Mode = "global" | "by-source"
type Shape = "stacked" | "overlay"

interface WindowSpec {
  label: string
  value: Window
  sinceSeconds: number
  bucketMs: number
}

const WINDOWS: readonly WindowSpec[] = [
  { label: "1h", value: "1h", sinceSeconds: 3600, bucketMs: 60_000 },
  { label: "6h", value: "6h", sinceSeconds: 6 * 3600, bucketMs: 5 * 60_000 },
  { label: "24h", value: "24h", sinceSeconds: 24 * 3600, bucketMs: 15 * 60_000 },
] as const

const STACK_PALETTE: readonly string[] = [
  "var(--category-1)",
  "var(--category-2)",
  "var(--category-3)",
  "var(--category-4)",
  "var(--category-5)",
  "var(--category-6)",
  "var(--category-8)",
] as const

const MAX_BY_SOURCE_SERIES = 6
const GLOBAL_SERIES_KEY = "count"

interface TimelineChartProps {
  className?: string
}

export function TimelineChart({ className }: TimelineChartProps) {
  const [window, setWindow] = useState<Window>("24h")
  const [mode, setMode] = useState<Mode>("global")
  const [shape, setShape] = useState<Shape>("stacked")

  const cfg = WINDOWS.find((w) => w.value === window) ?? WINDOWS[2]!

  const { data, isPending, isError } = useEventsHistogram({
    since: `${cfg.sinceSeconds}s`,
    bucket_ms: cfg.bucketMs,
    group_by: mode === "by-source" ? "source" : undefined,
  })

  const { rows, seriesKeys, total, peak } = useMemo(
    () => shapeHistogram(data?.buckets ?? [], mode),
    [data, mode],
  )

  return (
    <Card className={className}>
      <CardHeader className="flex flex-row flex-wrap items-start justify-between gap-3 pb-3">
        <div>
          <CardTitle className="text-base">Events over time</CardTitle>
          <div className="mt-0.5 text-xs text-muted-foreground">
            last {cfg.label} · {bucketLabel(cfg.bucketMs)} buckets
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {mode === "by-source" && (
            <Tabs value={shape} onValueChange={(v) => setShape(v as Shape)}>
              <TabsList className="h-8">
                <TabsTrigger value="stacked" className="px-3 text-xs">
                  Stacked
                </TabsTrigger>
                <TabsTrigger value="overlay" className="px-3 text-xs">
                  Overlay
                </TabsTrigger>
              </TabsList>
            </Tabs>
          )}
          <Tabs value={mode} onValueChange={(v) => setMode(v as Mode)}>
            <TabsList className="h-8">
              <TabsTrigger value="global" className="px-3 text-xs">
                Global
              </TabsTrigger>
              <TabsTrigger value="by-source" className="px-3 text-xs">
                By source
              </TabsTrigger>
            </TabsList>
          </Tabs>

          <Select value={window} onValueChange={(v) => setWindow(v as Window)}>
            <SelectTrigger className="h-8 w-20">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {WINDOWS.map((w) => (
                <SelectItem key={w.value} value={w.value}>
                  {w.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <div className="hidden text-right text-xs tabular-nums text-muted-foreground sm:block">
            <div>
              <span className="font-semibold text-foreground">
                {formatNumber(total)}
              </span>{" "}
              total
            </div>
            <div>peak {formatNumber(peak)}/bucket</div>
          </div>
        </div>
      </CardHeader>
      <CardContent className="h-56">
        {isPending ? (
          <LoadingSkeleton lines={5} />
        ) : isError ? (
          <EmptyState title="Unable to load timeline" />
        ) : total === 0 ? (
          <EmptyState title={`No events in the last ${cfg.label}`} />
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <ComposedChart data={rows} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
              <defs>
                {seriesKeys.map((key, i) => (
                  <linearGradient
                    key={key}
                    id={`tl-grad-${i}`}
                    x1="0"
                    y1="0"
                    x2="0"
                    y2="1"
                  >
                    <stop
                      offset="0%"
                      stopColor={
                        mode === "global"
                          ? "var(--brand)"
                          : STACK_PALETTE[i % STACK_PALETTE.length]
                      }
                      stopOpacity={0.45}
                    />
                    <stop
                      offset="100%"
                      stopColor={
                        mode === "global"
                          ? "var(--brand)"
                          : STACK_PALETTE[i % STACK_PALETTE.length]
                      }
                      stopOpacity={0}
                    />
                  </linearGradient>
                ))}
              </defs>
              <CartesianGrid strokeDasharray="3 3" opacity={0.2} vertical={false} />
              <XAxis
                dataKey="label"
                tick={{ fontSize: 10, fill: "var(--muted-foreground)" }}
                axisLine={false}
                tickLine={false}
                minTickGap={24}
              />
              <YAxis
                tick={{ fontSize: 10, fill: "var(--muted-foreground)" }}
                axisLine={false}
                tickLine={false}
                width={32}
                allowDecimals={false}
              />
              <Tooltip
                cursor={{ stroke: "var(--brand)", strokeOpacity: 0.3 }}
                contentStyle={{
                  background: "var(--popover)",
                  borderColor: "var(--border)",
                  borderRadius: "var(--radius-md)",
                  fontSize: "12px",
                }}
                labelStyle={{ color: "var(--muted-foreground)" }}
                itemStyle={{ color: "var(--foreground)" }}
              />
              {mode === "by-source" && (
                <Legend
                  verticalAlign="top"
                  align="right"
                  wrapperStyle={{ fontSize: "11px", paddingBottom: "4px" }}
                  iconSize={8}
                />
              )}
              {mode === "global"
                ? seriesKeys.map((key, i) => (
                    <Area
                      key={key}
                      type="monotone"
                      dataKey={key}
                      stroke="var(--brand)"
                      strokeWidth={1.75}
                      fill={`url(#tl-grad-${i})`}
                      name={key}
                    />
                  ))
                : shape === "stacked"
                  ? seriesKeys.map((key, i) => (
                      <Area
                        key={key}
                        type="monotone"
                        dataKey={key}
                        stackId="stack"
                        stroke={STACK_PALETTE[i % STACK_PALETTE.length]}
                        strokeWidth={1.25}
                        fill={`url(#tl-grad-${i})`}
                        name={key}
                      />
                    ))
                  : seriesKeys.map((key, i) => (
                      <Area
                        key={key}
                        type="monotone"
                        dataKey={key}
                        stroke={STACK_PALETTE[i % STACK_PALETTE.length]}
                        strokeWidth={1.75}
                        fill={STACK_PALETTE[i % STACK_PALETTE.length]}
                        fillOpacity={0.15}
                        activeDot={{ r: 3 }}
                        name={key}
                      />
                    ))}
            </ComposedChart>
          </ResponsiveContainer>
        )}
      </CardContent>
    </Card>
  )
}

function bucketLabel(bucketMs: number): string {
  const minutes = Math.round(bucketMs / 60_000)
  if (minutes < 60) return `${minutes}-minute`
  const hours = Math.round(minutes / 60)
  return `${hours}-hour`
}

function shapeHistogram(
  buckets: Array<{ t: number; count: number; by?: Record<string, number> }>,
  mode: Mode,
): {
  rows: Array<Record<string, string | number>>
  seriesKeys: string[]
  total: number
  peak: number
} {
  let total = 0
  let peak = 0
  for (const b of buckets) {
    total += b.count
    if (b.count > peak) peak = b.count
  }

  let seriesKeys: string[]
  if (mode === "global") {
    seriesKeys = [GLOBAL_SERIES_KEY]
  } else {
    const sourceTotals = new Map<string, number>()
    for (const b of buckets) {
      if (!b.by) continue
      for (const [k, v] of Object.entries(b.by)) {
        sourceTotals.set(k, (sourceTotals.get(k) ?? 0) + v)
      }
    }
    seriesKeys = Array.from(sourceTotals.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, MAX_BY_SOURCE_SERIES)
      .map(([k]) => k)
  }

  const rows = buckets.map((b) => {
    const row: Record<string, string | number> = {
      label: new Date(b.t).toLocaleTimeString(undefined, {
        hour: "2-digit",
        minute: "2-digit",
      }),
      _time: b.t,
    }
    if (mode === "global") {
      row[GLOBAL_SERIES_KEY] = b.count
    } else {
      for (const key of seriesKeys) {
        row[key] = b.by?.[key] ?? 0
      }
    }
    return row
  })

  return { rows, seriesKeys, total, peak }
}
