import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useNow } from "@/hooks/use-clock"
import { formatAbsoluteTime, formatTimeAgo } from "@/lib/format"
import { cn } from "@/lib/utils"

interface TimeAgoProps {
  value: string | Date | number
  className?: string
}

export function TimeAgo({ value, className }: TimeAgoProps) {
  const now = useNow()
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) {
    return <span className={className}>-</span>
  }
  const absolute = formatAbsoluteTime(date)
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <time
          dateTime={date.toISOString()}
          tabIndex={0}
          className={cn("rounded-sm outline-none focus-visible:ring-2 focus-visible:ring-ring", className)}
        >
          {formatTimeAgo(date, now)}
          <span className="sr-only">, {absolute}</span>
        </time>
      </TooltipTrigger>
      <TooltipContent>{absolute}</TooltipContent>
    </Tooltip>
  )
}
