import { Search, X } from "lucide-react"
import { useSearchParams } from "react-router"

import { Button } from "@/components/ui/button"
import { InputGroup, InputGroupAddon, InputGroupInput } from "@/components/ui/input-group"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { useEventsCountBy } from "@/hooks/use-events"
import { SINCE_PRESETS } from "@/lib/constants"
import type { EventFilters, Priority } from "@/lib/types"
import { cn } from "@/lib/utils"

import { MultiSelectFilter, type MultiSelectOption } from "./multi-select-filter"

interface EventFiltersBarProps {
  className?: string
}

const ANY_SINCE = "any"

export function EventFiltersBar({ className }: EventFiltersBarProps) {
  const [params, setParams] = useSearchParams()

  const filter = params.get("filter") ?? ""
  const priority = listParam(params, "priority")
  const source = listParam(params, "source")
  const rule = listParam(params, "rule")
  const hostname = listParam(params, "hostname")
  const tags = listParam(params, "tags")
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
    if (Array.isArray(values)) setListParam(next, key, values)
    else if (values) next.set(key, values)
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
      <InputGroup className="min-w-64 flex-1">
        <InputGroupAddon>
          <Search aria-hidden />
        </InputGroupAddon>
        <InputGroupInput
          placeholder="Search output, rule, tag, host…"
          value={filter}
          onChange={(e) => setParam("filter", e.target.value)}
          aria-label="Free-text search"
        />
      </InputGroup>

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
        <SelectTrigger className="h-9 w-fit min-w-36 shrink-0 whitespace-nowrap" aria-label="Time window">
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

// A list filter repeats its URL parameter once per value, as the API does: values may hold commas.
function listParam(params: URLSearchParams, key: string): string[] {
  return params
    .getAll(key)
    .map((s) => s.trim())
    .filter(Boolean)
}

/** Replaces the values of a list filter in params, one parameter per value. */
export function setListParam(params: URLSearchParams, key: string, values: readonly string[]): void {
  params.delete(key)
  for (const value of values) params.append(key, value)
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
    priority: listParam(params, "priority") as Priority[],
    source: listParam(params, "source"),
    rule: listParam(params, "rule"),
    hostname: listParam(params, "hostname"),
    tags: listParam(params, "tags"),
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
