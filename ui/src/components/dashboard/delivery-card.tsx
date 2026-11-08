import { ArrowRight } from "lucide-react"
import { Link } from "react-router"

import { Meter } from "@/components/common/meter"
import { OutputTypeIcon } from "@/components/common/output-type-icon"
import { StatusBadge } from "@/components/common/status-badge"
import { TimeAgo } from "@/components/common/time-ago"
import { Button } from "@/components/ui/button"
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { usePipelineStatus } from "@/hooks/use-pipeline"
import { errorMessage } from "@/lib/api-error"
import { formatNumber } from "@/lib/format"
import { lastSuccessOf, statusOf } from "@/lib/types"
import { cn } from "@/lib/utils"

import { byAttention, needsAttention, queueFilling } from "./attention"

/** Live delivery of every output, the ones that need attention first. */
export function DeliveryCard({ className }: { className?: string }) {
  const { data, isPending, error } = usePipelineStatus()
  const outputs = byAttention(data ?? [])
  return (
    <Card className={cn("@container/delivery gap-4 py-5 shadow-xs", className)}>
      <CardHeader className="px-5">
        <CardTitle className="text-base">Delivery</CardTitle>
        <CardDescription>Totals since start; outputs that need attention first.</CardDescription>
        <CardAction>
          <Button asChild variant="ghost" size="sm">
            <Link to="/pipeline">
              Pipeline <ArrowRight aria-hidden />
            </Link>
          </Button>
        </CardAction>
      </CardHeader>
      <CardContent className="px-0">
        {isPending ? (
          <div className="flex flex-col gap-2 px-5">
            {Array.from({ length: 4 }, (_, i) => (
              <Skeleton key={i} className="h-10 w-full" />
            ))}
          </div>
        ) : error ? (
          <p className="px-5 text-sm text-destructive">{errorMessage(error)}</p>
        ) : outputs.length === 0 ? (
          <p className="px-5 text-sm text-muted-foreground">No outputs configured.</p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className="pl-5">Output</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="text-right">Sent</TableHead>
                <TableHead className="hidden text-right @md/delivery:table-cell">Failed</TableHead>
                <TableHead className="hidden w-36 @lg/delivery:table-cell">Queue</TableHead>
                <TableHead className="hidden pr-5 text-right @xl/delivery:table-cell">Last delivery</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {outputs.map((s) => {
                const last = lastSuccessOf(s)
                return (
                  <TableRow key={s.name} className={cn(needsAttention(s) && "bg-status-error/[0.04] dark:bg-status-error/[0.07]")}>
                    <TableCell className="pl-5">
                      <div className="flex items-center gap-2.5">
                        <OutputTypeIcon driver={s.name} size="sm" />
                        <span className="font-medium">{s.name}</span>
                      </div>
                    </TableCell>
                    <TableCell>
                      <StatusBadge status={statusOf(s)} />
                    </TableCell>
                    <TableCell className="text-right tabular-nums">{formatNumber(s.sent_total)}</TableCell>
                    <TableCell className={cn("hidden text-right tabular-nums @md/delivery:table-cell", s.failed_total > 0 && "text-status-error-foreground")}>
                      {formatNumber(s.failed_total)}
                    </TableCell>
                    <TableCell className="hidden @lg/delivery:table-cell">
                      <div className="flex items-center gap-2">
                        <Meter
                          value={s.queue_depth}
                          max={s.queue_capacity}
                          label={`Queue ${s.name}`}
                          tone={queueFilling(s) ? "warning" : "neutral"}
                          className="flex-1"
                        />
                        <span className="w-12 text-right text-xs tabular-nums text-muted-foreground">{formatNumber(s.queue_depth)}</span>
                      </div>
                    </TableCell>
                    <TableCell className="hidden pr-5 text-right text-muted-foreground @xl/delivery:table-cell">
                      {last ? <TimeAgo value={last} /> : "never"}
                    </TableCell>
                  </TableRow>
                )
              })}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  )
}
