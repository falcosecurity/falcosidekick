import { ShieldAlert } from "lucide-react"

import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { cn } from "@/lib/utils"
import { useUIStore } from "@/stores/ui-store"

interface Props {
  compact?: boolean
}

export function AuthDisabledBanner({ compact }: Props) {
  const authEnabled = useUIStore((s) => s.authEnabled)
  if (authEnabled !== false) return null

  const message = "Authentication disabled — API is unauthenticated"

  if (compact) {
    return (
      <Tooltip>
        <TooltipTrigger asChild>
          <span
            className={cn(
              "inline-flex items-center gap-1.5 rounded-full border border-status-degraded/30 bg-status-degraded/10 px-2 py-0.5 text-[11px] font-medium text-status-degraded-foreground",
            )}
            aria-label={message}
          >
            <ShieldAlert className="size-3" aria-hidden />
            Auth off
          </span>
        </TooltipTrigger>
        <TooltipContent>{message}</TooltipContent>
      </Tooltip>
    )
  }

  return (
    <div
      role="status"
      className="flex items-center gap-2 rounded-md border border-status-degraded/30 bg-status-degraded/10 px-3 py-2 text-sm text-status-degraded-foreground"
    >
      <ShieldAlert className="size-4" aria-hidden />
      {message}
    </div>
  )
}
