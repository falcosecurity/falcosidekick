import {
  ArrowDown,
  ArrowUp,
  ArrowUpDown,
  ChevronLeft,
  ChevronRight,
  Inbox,
  RefreshCw,
} from "lucide-react"
import { useRef, useState } from "react"
import { useSearchParams } from "react-router"

import { SourceChip, TagChip } from "@/components/common/chips"
import { EmptyState } from "@/components/common/empty-state"
import { TableSkeleton } from "@/components/common/loading-skeleton"
import { PageHeader } from "@/components/common/page-header"
import { PriorityBadge } from "@/components/common/priority-badge"
import { TimeAgo } from "@/components/common/time-ago"
import { EventDetailDrawer } from "@/components/events/event-detail-drawer"
import { EventFiltersBar, useQueryFromUrl } from "@/components/events/event-filters"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useSearchEvents } from "@/hooks/use-events"
import { errorMessage } from "@/lib/api-error"
import { DEFAULT_PAGE_SIZE, PAGE_SIZES } from "@/lib/constants"
import { formatNumber } from "@/lib/format"
import type { Event, SortField } from "@/lib/types"
import { cn } from "@/lib/utils"

const MAX_VISIBLE_TAGS = 4

function SortHeader({
  active,
  desc,
  onClick,
  className,
  children,
}: {
  active: boolean
  desc: boolean
  onClick: () => void
  className?: string
  children: React.ReactNode
}) {
  const Icon = !active ? ArrowUpDown : desc ? ArrowDown : ArrowUp
  return (
    <TableHead
      className={cn("font-medium text-muted-foreground", className)}
      aria-sort={active ? (desc ? "descending" : "ascending") : undefined}
    >
      <button
        type="button"
        onClick={onClick}
        className={cn(
          "inline-flex items-center gap-1 rounded-sm hover:text-foreground focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring",
          active && "text-foreground",
        )}
      >
        {children}
        <Icon className="size-3" aria-hidden />
      </button>
    </TableHead>
  )
}

export function EventsPage() {
  const [params, setParams] = useSearchParams()
  const query = useQueryFromUrl()
  const { data, isPending, isError, error, refetch, isFetching, isPlaceholderData } = useSearchEvents(query)
  const [selected, setSelected] = useState<Event | null>(null)
  const opener = useRef<HTMLButtonElement | null>(null)
  const resultsRegion = useRef<HTMLDivElement>(null)

  const sortBy = (params.get("sort_by") as SortField | null) ?? "timestamp"
  const sortDesc = params.get("sort_desc") !== "false"

  function toggleSort(field: SortField) {
    setParams(
      (prev) => {
        const next = new URLSearchParams(prev)
        if (field === sortBy) {
          next.set("sort_desc", sortDesc ? "false" : "true")
        } else {
          next.set("sort_by", field)
          next.set("sort_desc", "true")
        }
        next.delete("page")
        return next
      },
      { replace: true },
    )
  }

  function goToPage(page: number) {
    setParams(
      (prev) => {
        const next = new URLSearchParams(prev)
        if (page <= 1) next.delete("page")
        else next.set("page", String(page))
        return next
      },
      { replace: true },
    )
  }

  function open(event: Event, trigger: HTMLButtonElement) {
    opener.current = trigger
    setSelected(event)
  }

  const limit = data?.limit ?? query.limit ?? DEFAULT_PAGE_SIZE
  const total = data?.total ?? 0
  const totalPages = Math.max(1, Math.ceil(total / limit))
  const page = data?.page ?? query.page ?? 1
  const start = (page - 1) * limit + 1
  const end = Math.min(total, page * limit)

  return (
    <div className="flex h-full flex-col gap-4">
      <PageHeader
        title="Events"
        description="Search, filter, and inspect Falco events as they flow through Falco Sidekick."
        actions={
          <Button variant="outline" size="sm" onClick={() => refetch()} disabled={isFetching}>
            <RefreshCw className={cn("mr-1 size-3.5", isFetching && "animate-spin")} aria-hidden />
            Refresh
          </Button>
        }
      />

      <EventFiltersBar />

      <div
        ref={resultsRegion}
        role="region"
        aria-label="Event results"
        tabIndex={-1}
        className="flex min-h-0 flex-1 flex-col overflow-hidden rounded-lg border bg-card outline-none focus-visible:ring-2 focus-visible:ring-ring"
      >
        {isPending ? (
          <div className="p-4">
            <TableSkeleton rows={10} />
          </div>
        ) : isError ? (
          <EmptyState
            title="Unable to load events"
            description={errorMessage(error)}
            action={
              <Button size="sm" variant="outline" onClick={() => refetch()}>
                Retry
              </Button>
            }
          />
        ) : !data || data.events.length === 0 ? (
          <EmptyState
            icon={<Inbox className="size-8" aria-hidden />}
            title="No events match"
            description="Adjust the filters above or widen the time window."
          />
        ) : (
          <div className="min-h-0 flex-1 overflow-auto">
            <Table className="table-fixed" aria-busy={isFetching || isPlaceholderData}>
              <TableHeader className="sticky top-0 z-10 bg-muted/40 backdrop-blur">
                <TableRow className="hover:bg-transparent">
                  <SortHeader
                    active={!isPlaceholderData && sortBy === "priority"}
                    desc={sortDesc}
                    onClick={() => toggleSort("priority")}
                    className="w-20"
                  >
                    Priority
                  </SortHeader>
                  <SortHeader
                    active={!isPlaceholderData && sortBy === "timestamp"}
                    desc={sortDesc}
                    onClick={() => toggleSort("timestamp")}
                    className="w-28"
                  >
                    Time
                  </SortHeader>
                  <SortHeader
                    active={!isPlaceholderData && sortBy === "rule"}
                    desc={sortDesc}
                    onClick={() => toggleSort("rule")}
                  >
                    Rule
                  </SortHeader>
                  <SortHeader
                    active={!isPlaceholderData && sortBy === "source"}
                    desc={sortDesc}
                    onClick={() => toggleSort("source")}
                    className="hidden w-28 md:table-cell"
                  >
                    Source
                  </SortHeader>
                  <TableHead className="hidden w-40 font-medium text-muted-foreground lg:table-cell">
                    Hostname
                  </TableHead>
                  <TableHead className="hidden w-64 font-medium text-muted-foreground xl:table-cell">
                    Tags
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.events.map((evt) => (
                  <TableRow key={evt.uuid} className="border-b-border/60 has-[button:focus-visible]:bg-muted/60">
                    <TableCell className="py-3">
                      <PriorityBadge priority={evt.priority} />
                    </TableCell>
                    <TableCell className="py-3 text-xs text-muted-foreground">
                      <TimeAgo value={evt.time} />
                    </TableCell>
                    <TableCell className="py-3">
                      <button
                        type="button"
                        title={evt.rule}
                        onClick={(e) => open(evt, e.currentTarget)}
                        className="block w-full truncate rounded-sm text-left font-medium text-foreground hover:underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring"
                      >
                        {evt.rule}
                      </button>
                    </TableCell>
                    <TableCell className="hidden py-3 md:table-cell">
                      <SourceChip source={evt.source} />
                    </TableCell>
                    <TableCell
                      className="hidden truncate py-3 font-mono text-xs text-muted-foreground lg:table-cell"
                      title={evt.hostname}
                    >
                      {evt.hostname ?? "-"}
                    </TableCell>
                    <TableCell className="hidden py-3 xl:table-cell">
                      <div className="flex flex-wrap gap-1">
                        {(evt.tags ?? []).slice(0, MAX_VISIBLE_TAGS).map((tag) => (
                          <TagChip key={tag} tag={tag} />
                        ))}
                        {(evt.tags?.length ?? 0) > MAX_VISIBLE_TAGS && (
                          <Badge variant="tag" className="border-border text-muted-foreground">
                            +{(evt.tags?.length ?? 0) - MAX_VISIBLE_TAGS}
                          </Badge>
                        )}
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </div>

      <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-muted-foreground">
        <span aria-live="polite" className="tabular-nums">
          {isError
            ? "Events unavailable"
            : data && data.events.length > 0
              ? `Showing ${formatNumber(start)}-${formatNumber(end)} of ${formatNumber(total)}`
              : data
                ? `${formatNumber(total)} events`
                : "Loading…"}
        </span>
        <div className="flex flex-wrap items-center gap-2">
          <span className="hidden sm:inline" aria-hidden>
            Rows per page
          </span>
          <Select
            value={String(query.limit ?? DEFAULT_PAGE_SIZE)}
            onValueChange={(v) => {
              setParams(
                (prev) => {
                  const next = new URLSearchParams(prev)
                  next.set("limit", v)
                  next.delete("page")
                  return next
                },
                { replace: true },
              )
            }}
          >
            <SelectTrigger className="h-8 w-20" aria-label="Rows per page">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {PAGE_SIZES.map((n) => (
                <SelectItem key={n} value={String(n)}>
                  {n}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Button variant="outline" size="sm" onClick={() => goToPage(page - 1)} disabled={page <= 1 || isPending}>
            <ChevronLeft className="mr-1 size-3.5" aria-hidden />
            Previous
          </Button>
          <span className="tabular-nums">
            Page {page} of {totalPages}
          </span>
          <Button
            variant="outline"
            size="sm"
            onClick={() => goToPage(page + 1)}
            disabled={page >= totalPages || isPending}
          >
            Next
            <ChevronRight className="ml-1 size-3.5" aria-hidden />
          </Button>
        </div>
      </div>

      <EventDetailDrawer
        event={selected}
        open={selected !== null}
        onClose={() => setSelected(null)}
        onCloseAutoFocus={(e) => {
          e.preventDefault()
          const target = opener.current?.isConnected ? opener.current : resultsRegion.current
          target?.focus()
        }}
      />
    </div>
  )
}

export default EventsPage
