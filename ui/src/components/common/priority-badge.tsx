import { PRIORITY_LABELS, type Priority } from "@/lib/types"
import { PRIORITY_LABEL_SHORT } from "@/lib/constants"
import { cn } from "@/lib/utils"

interface PriorityBadgeProps {
  priority: Priority
  short?: boolean
  className?: string
}

const TOKEN: Record<Priority, string> = {
  emergency: "bg-priority-emergency/15 text-priority-emergency-foreground border-priority-emergency/30",
  alert: "bg-priority-alert/15 text-priority-alert-foreground border-priority-alert/30",
  critical: "bg-priority-critical/15 text-priority-critical-foreground border-priority-critical/30",
  error: "bg-priority-error/15 text-priority-error-foreground border-priority-error/30",
  warning: "bg-priority-warning/15 text-priority-warning-foreground border-priority-warning/30",
  notice: "bg-priority-notice/15 text-priority-notice-foreground border-priority-notice/30",
  informational: "bg-priority-info/15 text-priority-info-foreground border-priority-info/30",
  debug: "bg-priority-debug/15 text-priority-debug-foreground border-priority-debug/30",
}

export function PriorityBadge({ priority, short = true, className }: PriorityBadgeProps) {
  const label = short ? PRIORITY_LABEL_SHORT[priority] : PRIORITY_LABELS[priority]
  return (
    <span
      aria-label={`priority ${priority}`}
      className={cn(
        "inline-flex items-center rounded border px-1.5 py-0.5 font-mono text-[11px] font-semibold uppercase tracking-wide tabular-nums",
        TOKEN[priority],
        className,
      )}
    >
      {label}
    </span>
  )
}
