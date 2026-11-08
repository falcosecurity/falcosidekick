import { DatabaseZap } from "lucide-react"

import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { cn } from "@/lib/utils"

const LABEL = "Event source: the Events page and the dashboard read from it"

// EventSourceMark marks the output the UI reads events back from. Like OriginMark it is an icon with
// a tooltip and sr-only text, not focusable because it sits inside buttons.
export function EventSourceMark({ className }: { className?: string }) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className={cn("shrink-0 text-brand", className)}>
          <DatabaseZap className="size-3.5" aria-hidden />
          <span className="sr-only">{LABEL}</span>
        </span>
      </TooltipTrigger>
      <TooltipContent>{LABEL}</TooltipContent>
    </Tooltip>
  )
}
