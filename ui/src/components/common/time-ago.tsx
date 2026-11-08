import { useEffect, useState } from "react"

import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { formatAbsoluteTime, formatTimeAgo } from "@/lib/format"

interface TimeAgoProps {
  value: string | Date | number
  className?: string
}

export function TimeAgo({ value, className }: TimeAgoProps) {
  const [, forceTick] = useState(0)

  useEffect(() => {
    const id = window.setInterval(() => forceTick((n) => n + 1), 30_000)
    return () => window.clearInterval(id)
  }, [])

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <time className={className} dateTime={new Date(value).toISOString()}>
          {formatTimeAgo(value)}
        </time>
      </TooltipTrigger>
      <TooltipContent>{formatAbsoluteTime(value)}</TooltipContent>
    </Tooltip>
  )
}
