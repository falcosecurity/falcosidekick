import { Search, X } from "lucide-react"
import { useSearchParams } from "react-router"

import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { useEventsCountBy } from "@/hooks/use-events"
import { SINCE_PRESETS } from "@/lib/constants"
import { PRIORITIES, PRIORITY_LABELS, type EventFilters, type Priority } from "@/lib/types"
import { cn } from "@/lib/utils"

import { MultiSelectFilter, type MultiSelectOption } from "./multi-select-filter"

interface EventFiltersBarProps {
  className?: string
}

const ANY_SINCE = "any"

const PRIORITY_OPTIONS: readonly MultiSelectOption[] = PRIORITIES.map((p) => ({
  value: p,
  label: PRIORITY_LABELS[p],
}))

export function EventFiltersBar({ className }: EventFiltersBarProps) {
  const [params, setParams] = useSearchParams()

  const filter = params.get("filter") ?? ""
  const priority = csvFromParam(params.get("priority"))
  const source = csvFromParam(params.get("source"))
  const rule = csvFromParam(params.get("rule"))
  const hostname = csvFromParam(params.get("hostname"))
  const tags = csvFromParam(params.get("tags"))
  const since = params.get("since") ?? ""

  const activeFilters: EventFilters = {
    filter: filter || undefined,
    priority: priority as Priority[],
    source,
    rule,
    hostname,
    tags,
    since: since || undefined,
  }

  const sourceOptions = useFacetOptions("source", activeFilters)
  const ruleOptions = useFacetOptions("rule", activeFilters)
  const hostOptions = useFacetOptions("hostname", activeFilters)
  const tagOptions = useFacetOptions("tags", activeFilters)

  function setParam(key: string, values: string[] | string) {
    const next = new URLSearchParams(params)
    const value = Array.isArray(values) ? values.join(",") : values
    if (value) next.set(key, value)
    else next.delete(key)
    next.delete("page")
    setParams(next, { replace: true })
  }

  function clearAll() {
    const next = new URLSearchParams()
    const limit = params.get("limit")
    if (limit) next.set("limit", limit)
    setParams(next, { replace: true })
  }

  const hasAny =
    filter ||
    priority.length > 0 ||
    source.length > 0 ||
    rule.length > 0 ||
    hostname.length > 0 ||
    tags.length > 0 ||
    since

  return (
    <div className={cn("flex flex-wrap items-center gap-2", className)}>
      <div className="relative min-w-64 flex-1">
        <Search
          className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground"
          aria-hidden
        />
        <Input
          className="pl-8"
          placeholder="Search output, rule, tag, host…"
          value={filter}
          onChange={(e) => setParam("filter", e.target.value)}
          aria-label="Free-text search"
        />
      </div>

      <MultiSelectFilter
        label="Priority"
        placeholder="Priority"
        options={PRIORITY_OPTIONS}
        values={priority}
        onChange={(v) => setParam("priority", v)}
      />
      <MultiSelectFilter
        label="Source"
        placeholder="Source"
        options={sourceOptions}
        values={source}
        onChange={(v) => setParam("source", v)}
      />
      <MultiSelectFilter
        label="Rule"
        placeholder="Rule"
        options={ruleOptions}
        values={rule}
        onChange={(v) => setParam("rule", v)}
        allowCustom
      />
      <MultiSelectFilter
        label="Hostname"
        placeholder="Hostname"
        options={hostOptions}
        values={hostname}
        onChange={(v) => setParam("hostname", v)}
        allowCustom
      />
      <MultiSelectFilter
        label="Tags"
        placeholder="Tags"
        options={tagOptions}
        values={tags}
        onChange={(v) => setParam("tags", v)}
        allowCustom
      />

      <Select
        value={since || ANY_SINCE}
        onValueChange={(v) => setParam("since", v === ANY_SINCE ? "" : v)}
      >
        <SelectTrigger className="h-9 w-36" aria-label="Time window">
          <SelectValue placeholder="Any time" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value={ANY_SINCE}>Any time</SelectItem>
          {SINCE_PRESETS.map((p) => (
            <SelectItem key={p.value} value={p.value}>
              {p.label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>

      {hasAny && (
        <Button variant="ghost" size="sm" onClick={clearAll} aria-label="Clear all filters">
          <X className="mr-1 size-3.5" aria-hidden />
          Clear all
        </Button>
      )}
    </div>
  )
}

function csvFromParam(value: string | null): string[] {
  if (!value) return []
  return value
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
}

type FacetField = "source" | "rule" | "hostname" | "tags"

function filtersExcept(filters: EventFilters, field: FacetField): EventFilters {
  const { [field]: _dropped, ...rest } = filters
  void _dropped
  return rest
}

function useFacetOptions(field: FacetField, filters: EventFilters): MultiSelectOption[] {
  const { data } = useEventsCountBy(field, filtersExcept(filters, field))
  if (!data) return []
  return Object.entries(data)
    .sort((a, b) => b[1] - a[1])
    .map(([value, count]) => ({ value, label: value, hint: String(count) }))
}

export function useFiltersFromUrl() {
  const [params] = useSearchParams()
  return {
    filter: params.get("filter") || undefined,
    priority: csvFromParam(params.get("priority")) as Priority[],
    source: csvFromParam(params.get("source")),
    rule: csvFromParam(params.get("rule")),
    hostname: csvFromParam(params.get("hostname")),
    tags: csvFromParam(params.get("tags")),
    since: params.get("since") || undefined,
  }
}

export function useQueryFromUrl() {
  const [params] = useSearchParams()
  const filters = useFiltersFromUrl()
  const limit = Number(params.get("limit")) || 50
  const sortBy = (params.get("sort_by") ?? "timestamp") as
    | "timestamp"
    | "priority"
    | "rule"
    | "source"
  const sortDesc = params.get("sort_desc") !== "false"
  return {
    ...filters,
    priority: filters.priority.length > 0 ? filters.priority : undefined,
    source: filters.source.length > 0 ? filters.source : undefined,
    rule: filters.rule.length > 0 ? filters.rule : undefined,
    hostname: filters.hostname.length > 0 ? filters.hostname : undefined,
    tags: filters.tags.length > 0 ? filters.tags : undefined,
    page: Number(params.get("page")) || 1,
    limit,
    sort_by: sortBy,
    sort_desc: sortDesc,
  }
}
