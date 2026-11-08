import { Badge } from "@/components/ui/badge"
import type { OutputHealth } from "@/lib/types"
import { cn } from "@/lib/utils"

interface StatusBadgeProps {
  status: OutputHealth
  className?: string
}

const TOKEN: Record<OutputHealth, string> = {
  ok: "bg-status-ok/15 text-status-ok-foreground border-status-ok/30",
  idle: "bg-muted text-muted-foreground border-border",
  failed: "bg-status-error/15 text-status-error-foreground border-status-error/30 border-dashed",
  error: "bg-status-error/15 text-status-error-foreground border-status-error/30",
  degraded: "bg-status-degraded/15 text-status-degraded-foreground border-status-degraded/30",
  unknown: "bg-status-unknown/10 text-status-unknown-foreground border-status-unknown/30",
}

const DOT: Record<OutputHealth, string> = {
  ok: "bg-status-ok",
  idle: "bg-muted-foreground",
  failed: "bg-status-error",
  error: "bg-status-error",
  degraded: "bg-status-degraded",
  unknown: "bg-status-unknown",
}

export function StatusBadge({ status, className }: StatusBadgeProps) {
  return (
    <Badge variant="status" data-status={status} className={cn(TOKEN[status], className)}>
      <span className={cn("size-1.5 rounded-full", DOT[status])} aria-hidden />
      <span className="sr-only">status </span>
      {status}
    </Badge>
  )
}
