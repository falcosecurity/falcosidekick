import type { OutputStatusState } from "@/lib/types"
import { cn } from "@/lib/utils"

interface StatusBadgeProps {
  status: OutputStatusState
  className?: string
}

const TOKEN: Record<OutputStatusState, string> = {
  ok: "bg-status-ok/15 text-status-ok-foreground border-status-ok/30",
  idle: "bg-muted text-muted-foreground border-border",
  error: "bg-status-error/15 text-status-error-foreground border-status-error/30",
  degraded: "bg-status-degraded/15 text-status-degraded-foreground border-status-degraded/30",
  disabled: "bg-status-disabled/10 text-status-disabled-foreground border-status-disabled/30",
  unknown: "bg-status-unknown/10 text-status-unknown-foreground border-status-unknown/30",
}

const DOT: Record<OutputStatusState, string> = {
  ok: "bg-status-ok",
  idle: "bg-muted-foreground",
  error: "bg-status-error",
  degraded: "bg-status-degraded",
  disabled: "bg-status-disabled",
  unknown: "bg-status-unknown",
}

export function StatusBadge({ status, className }: StatusBadgeProps) {
  return (
    <span
      role="status"
      aria-label={`status ${status}`}
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-xs font-medium capitalize",
        TOKEN[status],
        className,
      )}
    >
      <span className={cn("size-1.5 rounded-full", DOT[status])} aria-hidden />
      {status}
    </span>
  )
}
