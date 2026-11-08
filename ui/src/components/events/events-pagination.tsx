import { useSearchParams } from "react-router"

import {
  Pagination,
  PaginationContent,
  PaginationEllipsis,
  PaginationItem,
  PaginationLink,
  PaginationNext,
  PaginationPrevious,
} from "@/components/ui/pagination"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { PAGE_SIZES } from "@/lib/constants"
import { formatNumber } from "@/lib/format"
import { cn } from "@/lib/utils"

interface EventsPaginationProps {
  page: number
  totalPages: number
  limit: number
  summary: string
  disabled?: boolean
}

/** Pages around the current one, with gaps shown as an ellipsis: 1 … 4 5 6 … 31. */
export function pageWindow(page: number, totalPages: number): (number | "gap")[] {
  const pages = new Set([1, totalPages, page - 1, page, page + 1].filter((p) => p >= 1 && p <= totalPages))
  const sorted = [...pages].sort((a, b) => a - b)
  const out: (number | "gap")[] = []
  sorted.forEach((p, i) => {
    if (i > 0 && p - sorted[i - 1]! > 1) out.push("gap")
    out.push(p)
  })
  return out
}

export function EventsPagination({ page, totalPages, limit, summary, disabled }: EventsPaginationProps) {
  const [params, setParams] = useSearchParams()

  const hrefFor = (target: number) => {
    const next = new URLSearchParams(params)
    if (target <= 1) next.delete("page")
    else next.set("page", String(target))
    return `?${next.toString()}`
  }
  // Real links, so a page opens in a new tab; a plain click stays in the app.
  const go = (target: number) => (event: React.MouseEvent) => {
    if (event.metaKey || event.ctrlKey || event.shiftKey || event.button !== 0) return
    event.preventDefault()
    if (disabled || target < 1 || target > totalPages || target === page) return
    setParams(new URLSearchParams(hrefFor(target).slice(1)), { replace: true })
  }
  const setLimit = (value: string) => {
    const next = new URLSearchParams(params)
    next.set("limit", value)
    next.delete("page")
    setParams(next, { replace: true })
  }
  const off = (blocked: boolean) => (blocked || disabled ? "pointer-events-none opacity-50" : undefined)

  return (
    <div className="flex flex-wrap items-center justify-between gap-3 text-xs text-muted-foreground">
      <span aria-live="polite" className="tabular-nums">
        {summary}
      </span>
      <div className="flex flex-wrap items-center gap-3">
        <Select value={String(limit)} onValueChange={setLimit}>
          <SelectTrigger size="sm" className="w-auto min-w-32" aria-label="Rows per page">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {PAGE_SIZES.map((n) => (
              <SelectItem key={n} value={String(n)}>
                {n} per page
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Pagination className="mx-0 w-auto">
          <PaginationContent>
            <PaginationItem>
              <PaginationPrevious href={hrefFor(page - 1)} onClick={go(page - 1)} aria-disabled={page <= 1} className={off(page <= 1)} />
            </PaginationItem>
            {pageWindow(page, totalPages).map((p, i) =>
              p === "gap" ? (
                <PaginationItem key={`gap-${i}`} className="hidden sm:block">
                  <PaginationEllipsis />
                </PaginationItem>
              ) : (
                <PaginationItem key={p} className={cn(p !== page && "hidden sm:block")}>
                  <PaginationLink href={hrefFor(p)} onClick={go(p)} isActive={p === page} className="tabular-nums">
                    {formatNumber(p)}
                  </PaginationLink>
                </PaginationItem>
              ),
            )}
            <PaginationItem>
              <PaginationNext href={hrefFor(page + 1)} onClick={go(page + 1)} aria-disabled={page >= totalPages} className={off(page >= totalPages)} />
            </PaginationItem>
          </PaginationContent>
        </Pagination>
      </div>
    </div>
  )
}
