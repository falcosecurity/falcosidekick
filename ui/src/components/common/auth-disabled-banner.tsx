import { ShieldAlert } from "lucide-react"

import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { AUTH_UNAVAILABLE_MESSAGE } from "@/lib/auth"

interface Props {
  compact?: boolean
}

export function AuthDisabledBanner({ compact }: Props) {
  if (compact) {
    return (
      <Tooltip>
        <TooltipTrigger asChild>
          <span
            className="inline-flex h-8 items-center gap-1.5 rounded-full border border-status-degraded/30 bg-status-degraded/10 px-2 text-2xs font-medium text-status-degraded-foreground"
            aria-label={AUTH_UNAVAILABLE_MESSAGE}
          >
            <ShieldAlert className="size-3.5" aria-hidden />
            <span className="hidden sm:inline">Auth off</span>
          </span>
        </TooltipTrigger>
        <TooltipContent>{AUTH_UNAVAILABLE_MESSAGE}</TooltipContent>
      </Tooltip>
    )
  }

  return (
    <div className="flex items-center gap-2 rounded-md border border-status-degraded/30 bg-status-degraded/10 px-3 py-2 text-sm text-status-degraded-foreground">
      <ShieldAlert className="size-4" aria-hidden />
      {AUTH_UNAVAILABLE_MESSAGE}
    </div>
  )
}
