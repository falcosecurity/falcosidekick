import { cn } from "@/lib/utils"

export type MeterTone = "ok" | "warning" | "error" | "brand" | "neutral"

const FILL: Record<MeterTone, string> = {
  ok: "bg-status-ok",
  warning: "bg-status-degraded",
  error: "bg-status-error",
  brand: "bg-brand/70",
  neutral: "bg-muted-foreground",
}

interface MeterProps {
  value: number
  max: number
  label: string
  tone?: MeterTone
  size?: "sm" | "md"
  /** Hidden from assistive technology because the figure is already in the text next to it. */
  decorative?: boolean
  fillClassName?: string
  className?: string
}

export function meterPercent(value: number, max: number): number {
  if (!(max > 0) || !Number.isFinite(value)) return 0
  return Math.max(0, Math.min(100, (value / max) * 100))
}

export function Meter({ value, max, label, tone = "brand", size = "sm", decorative = false, fillClassName, className }: MeterProps) {
  const percent = meterPercent(value, max)
  const bounded = Math.max(0, Math.min(Math.max(max, 0), value))
  return (
    <div
      role={decorative ? undefined : "meter"}
      aria-hidden={decorative || undefined}
      aria-label={decorative ? undefined : label}
      aria-valuemin={decorative ? undefined : 0}
      aria-valuemax={decorative ? undefined : Math.max(max, 0)}
      aria-valuenow={decorative ? undefined : bounded}
      className={cn("w-full overflow-hidden rounded-full bg-muted", size === "sm" ? "h-1" : "h-2", className)}
    >
      <div className={cn("h-full rounded-full", FILL[tone], fillClassName)} style={{ width: `${percent}%` }} />
    </div>
  )
}
