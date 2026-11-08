import { Copy, Download, X } from "lucide-react"
import { useState } from "react"
import { toast } from "sonner"

import { Button } from "@/components/ui/button"
import { Spinner } from "@/components/ui/spinner"
import { api } from "@/lib/api-client"
import { errorMessage } from "@/lib/api-error"
import { downloadJSON, exportFileName } from "@/lib/download"
import { formatNumber } from "@/lib/format"
import type { Event, SearchQuery } from "@/lib/types"

/** The most events one export reads: the largest page the search API returns. */
export const EXPORT_LIMIT = 10_000

/** Actions on the selected events: copy or download them as JSON, or clear the selection. */
export function SelectionBar({ events, onClear }: { events: Event[]; onClear: () => void }) {
  const count = events.length
  const noun = count === 1 ? "event" : "events"
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(events, null, 2))
      toast.success(`${formatNumber(count)} ${noun} copied as JSON`)
    } catch {
      toast.error("The browser did not allow copying")
    }
  }
  return (
    <div role="toolbar" aria-label="Selected events" className="flex flex-wrap items-center gap-2 rounded-lg border bg-muted/40 px-3 py-2 text-sm">
      <span className="font-medium tabular-nums">
        {formatNumber(count)} {noun} selected
      </span>
      <span className="ml-auto flex flex-wrap gap-2">
        <Button size="sm" variant="outline" onClick={copy}>
          <Copy aria-hidden /> Copy JSON
        </Button>
        <Button size="sm" variant="outline" onClick={() => downloadJSON(exportFileName("falco-events"), events)}>
          <Download aria-hidden /> Export JSON
        </Button>
        <Button size="sm" variant="ghost" onClick={onClear}>
          <X aria-hidden /> Clear
        </Button>
      </span>
    </div>
  )
}

/** Downloads every event the current filters match, in the current order, up to EXPORT_LIMIT. */
export function ExportAllButton({ query, total }: { query: SearchQuery; total: number }) {
  const [busy, setBusy] = useState(false)
  const exportAll = async () => {
    setBusy(true)
    try {
      const result = await api.searchEvents({ ...query, page: 1, limit: EXPORT_LIMIT })
      downloadJSON(exportFileName("falco-events"), result.events)
      toast.success(
        result.total > result.events.length
          ? `Exported the first ${formatNumber(result.events.length)} of ${formatNumber(result.total)} events; narrow the filters for the rest`
          : `Exported ${formatNumber(result.events.length)} events`,
      )
    } catch (error) {
      toast.error(`Export failed: ${errorMessage(error)}`)
    } finally {
      setBusy(false)
    }
  }
  return (
    <Button variant="outline" size="sm" onClick={exportAll} disabled={busy || total === 0}>
      {busy ? <Spinner /> : <Download aria-hidden />}
      Export all matching
    </Button>
  )
}
