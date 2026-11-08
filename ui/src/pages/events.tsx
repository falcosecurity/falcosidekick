import {
  ArrowDown,
  ArrowUp,
  ArrowUpDown,
  Inbox,
  RefreshCw,
} from "lucide-react"
import { useRef, useState } from "react"
import { useSearchParams } from "react-router"

import { SourceChip, TagChip } from "@/components/common/chips"
import { EmptyState } from "@/components/common/empty-state"
import { ErrorState } from "@/components/common/error-state"
import { TableSkeleton } from "@/components/common/loading-skeleton"
import { PageHeader } from "@/components/common/page-header"
import { PriorityBadge } from "@/components/common/priority-badge"
import { TimeAgo } from "@/components/common/time-ago"
import { EventDetailDrawer } from "@/components/events/event-detail-drawer"
import { EventFiltersBar, useQueryFromUrl } from "@/components/events/event-filters"
import { ExportAllButton, SelectionBar } from "@/components/events/event-export"
import { EventsPagination } from "@/components/events/events-pagination"
import { PriorityQuickFilter } from "@/components/events/priority-quick-filter"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card } from "@/components/ui/card"
import { Checkbox } from "@/components/ui/checkbox"
import { Field, FieldLabel } from "@/components/ui/field"
import { Switch } from "@/components/ui/switch"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useSearchEvents } from "@/hooks/use-events"
import { errorMessage } from "@/lib/api-error"
import { DEFAULT_PAGE_SIZE } from "@/lib/constants"
import { formatClock, formatNumber } from "@/lib/format"
import type { Event, SortField } from "@/lib/types"
import { cn } from "@/lib/utils"
import { useUIStore } from "@/stores/ui-store"

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
  const live = useUIStore((s) => s.eventsLive)
  const setLive = useUIStore((s) => s.setEventsLive)
  const [selected, setSelected] = useState<Event | null>(null)
  // Picked events by uuid; the selection survives paging and filtering until it is cleared.
  const [picked, setPicked] = useState<ReadonlyMap<string, Event>>(new Map())
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

  const pageEvents = data?.events ?? []
  const pagePicked = pageEvents.filter((e) => picked.has(e.uuid)).length
  const pageState: boolean | "indeterminate" =
    pagePicked === 0 ? false : pagePicked === pageEvents.length ? true : "indeterminate"

  function pick(events: readonly Event[], on: boolean) {
    setPicked((prev) => {
      const next = new Map(prev)
      for (const e of events) {
        if (on) next.set(e.uuid, e)
        else next.delete(e.uuid)
      }
      return next
    })
  }

  return (
    <div className="flex h-full flex-col gap-4">
      <PageHeader
        title="Events"
        description={
          live
            ? "Search, filter and inspect Falco events. Live: the list follows the refresh interval."
            : "Search, filter and inspect Falco events. The list stays still while you work: it updates when you refresh or change the filters."
        }
        actions={
          <>
            <Field orientation="horizontal" className="w-auto gap-2">
              <Switch id="events-live" checked={live} onCheckedChange={setLive} />
              <FieldLabel htmlFor="events-live" className="font-normal">
                Live
              </FieldLabel>
            </Field>
            <ExportAllButton query={query} total={total} />
            <Button variant="outline" size="sm" onClick={() => refetch()} disabled={isFetching}>
              <RefreshCw className={cn("size-3.5", isFetching && "animate-spin")} aria-hidden />
              Refresh
            </Button>
          </>
        }
      />

      <div className="flex flex-col gap-3">
        <EventFiltersBar />
        <PriorityQuickFilter />
        {picked.size > 0 && <SelectionBar events={[...picked.values()]} onClear={() => setPicked(new Map())} />}
      </div>

      <Card
        ref={resultsRegion}
        role="region"
        aria-label="Event results"
        tabIndex={-1}
        className="min-h-0 flex-1 gap-0 overflow-hidden py-0 shadow-xs outline-none focus-visible:ring-2 focus-visible:ring-ring"
      >
        {isPending ? (
          <div className="p-4">
            <TableSkeleton rows={10} />
          </div>
        ) : isError ? (
          <ErrorState className="m-4" title="Unable to load events" description={errorMessage(error)} onRetry={() => refetch()} />
        ) : !data || data.events.length === 0 ? (
          <EmptyState
            headingLevel={2}
            icon={<Inbox aria-hidden />}
            title="No events match"
            description="Adjust the filters above or widen the time window."
          />
        ) : (
          <div className="min-h-0 flex-1 overflow-auto">
            <Table className="table-fixed" aria-busy={isFetching || isPlaceholderData}>
              <TableHeader className="sticky top-0 z-10 bg-muted/40 backdrop-blur">
                <TableRow className="hover:bg-transparent">
                  <TableHead className="w-10 pr-0">
                    <Checkbox
                      checked={pageState}
                      onCheckedChange={(on) => pick(pageEvents, on === true)}
                      aria-label="Select every event on this page"
                    />
                  </TableHead>
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
                    className="w-24 sm:w-36"
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
                  <TableHead className="hidden w-44 font-medium text-muted-foreground xl:table-cell 2xl:w-56">
                    Tags
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.events.map((evt) => (
                  <TableRow
                    key={evt.uuid}
                    data-state={picked.has(evt.uuid) ? "selected" : undefined}
                    className="cursor-pointer border-b-border/60 has-[button:focus-visible]:bg-muted/60"
                    onClick={(e) => {
                      // The rule button opens the event; a click elsewhere on the row does the same.
                      if ((e.target as HTMLElement).closest("button, a, [data-select-cell]")) return
                      const trigger = e.currentTarget.querySelector<HTMLButtonElement>("button[data-open-event]")
                      if (trigger) open(evt, trigger)
                    }}
                  >
                    <TableCell data-select-cell className="w-10 cursor-default pr-0 align-middle">
                      <Checkbox
                        checked={picked.has(evt.uuid)}
                        onCheckedChange={(on) => pick([evt], on === true)}
                        aria-label={`Select ${evt.rule} at ${formatClock(evt.time)}`}
                      />
                    </TableCell>
                    <TableCell className="py-2.5 align-middle">
                      <PriorityBadge priority={evt.priority} />
                    </TableCell>
                    <TableCell className="py-2.5 align-middle">
                      <div className="hidden font-mono text-xs tabular-nums sm:block">{formatClock(evt.time)}</div>
                      <TimeAgo value={evt.time} interactive={false} className="block text-xs text-muted-foreground" />
                    </TableCell>
                    <TableCell className="py-2.5 align-middle">
                      <button
                        type="button"
                        data-open-event
                        title={evt.rule}
                        onClick={(e) => open(evt, e.currentTarget)}
                        className="block w-full truncate rounded-sm text-left font-medium text-foreground hover:underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring"
                      >
                        {evt.rule}
                      </button>
                      <p className="truncate text-xs text-muted-foreground" title={evt.output}>
                        {evt.output}
                      </p>
                    </TableCell>
                    <TableCell className="hidden py-2.5 align-middle md:table-cell">
                      <SourceChip source={evt.source} />
                    </TableCell>
                    <TableCell
                      className="hidden truncate py-2.5 align-middle font-mono text-xs text-muted-foreground lg:table-cell"
                      title={evt.hostname}
                    >
                      {evt.hostname ?? "-"}
                    </TableCell>
                    <TableCell className="hidden py-2.5 align-middle xl:table-cell">
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
      </Card>

      <EventsPagination
        page={page}
        totalPages={totalPages}
        limit={limit}
        disabled={isPending}
        summary={
          isError
            ? "Events unavailable"
            : data && data.events.length > 0
              ? `Showing ${formatNumber(start)}-${formatNumber(end)} of ${formatNumber(total)}`
              : data
                ? `${formatNumber(total)} events`
                : "Loading…"
        }
      />

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
