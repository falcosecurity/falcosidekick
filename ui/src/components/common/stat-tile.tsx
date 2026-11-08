import type { ReactNode } from "react"

import { cn } from "@/lib/utils"

export type StatTone = "ok" | "error" | "warning" | "neutral"

const TONE: Record<StatTone, { container: string; value: string }> = {
  ok: { container: "border-l-status-ok bg-muted/30", value: "text-status-ok-foreground" },
  error: { container: "border-l-status-error bg-status-error/10", value: "text-status-error-foreground" },
  warning: { container: "border-l-status-degraded bg-status-degraded/10", value: "text-status-degraded-foreground" },
  neutral: { container: "border-l-border bg-muted/30", value: "text-foreground" },
}

interface StatTileProps {
  label: string
  value?: ReactNode
  tone?: StatTone
  className?: string
  valueClassName?: string
  children?: ReactNode
}

/** The list that holds stat tiles. */
export function StatGrid({ className, children }: { className?: string; children: ReactNode }) {
  return <dl className={cn("grid grid-cols-3 gap-2 text-sm", className)}>{children}</dl>
}

/** One labelled figure; render inside a `StatGrid`. */
export function StatTile({ label, value, tone = "neutral", className, valueClassName, children }: StatTileProps) {
  return (
    <div className={cn("flex min-w-0 flex-col gap-0.5 rounded-md border-l-2 px-2 py-1.5", TONE[tone].container, className)}>
      <dt className="text-2xs font-medium uppercase tracking-wider text-muted-foreground">{label}</dt>
      <dd className={cn("min-w-0 text-sm font-semibold tabular-nums [overflow-wrap:anywhere]", TONE[tone].value, valueClassName)}>
        {value}
        {children}
      </dd>
    </div>
  )
}
