import { useIsFetching, useQueryClient } from "@tanstack/react-query"
import { RefreshCw } from "lucide-react"

import { Button } from "@/components/ui/button"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { cn } from "@/lib/utils"
import { REFRESH_OPTIONS, useUIStore } from "@/stores/ui-store"

export function RefreshIntervalSelector() {
  const interval = useUIStore((s) => s.refreshIntervalMs)
  const setInterval = useUIStore((s) => s.setRefreshIntervalMs)
  const queryClient = useQueryClient()
  const fetchingCount = useIsFetching()

  return (
    <div className="flex items-center gap-1">
      <Tooltip>
        <TooltipTrigger asChild>
          <Button
            variant="ghost"
            size="icon"
            className="h-8 w-8"
            aria-label="Refresh all data now"
            onClick={() => queryClient.invalidateQueries()}
          >
            <RefreshCw
              className={cn("size-4", fetchingCount > 0 && "animate-spin")}
              aria-hidden
            />
          </Button>
        </TooltipTrigger>
        <TooltipContent>Refresh now</TooltipContent>
      </Tooltip>
      <Select
        value={String(interval)}
        onValueChange={(v) => setInterval(Number(v))}
      >
        <SelectTrigger
          className="h-8 w-20"
          aria-label="Auto-refresh interval"
        >
          <SelectValue />
        </SelectTrigger>
        <SelectContent align="end">
          {REFRESH_OPTIONS.map((opt) => (
            <SelectItem key={opt.value} value={String(opt.value)}>
              {opt.label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  )
}
