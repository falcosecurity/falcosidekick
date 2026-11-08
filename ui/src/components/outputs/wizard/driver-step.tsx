import { Check, DatabaseZap, Search } from "lucide-react"
import { useMemo, useState } from "react"

import { OutputTypeIcon } from "@/components/common/output-type-icon"
import { Badge } from "@/components/ui/badge"
import { Empty, EmptyDescription, EmptyHeader, EmptyTitle } from "@/components/ui/empty"
import { FieldDescription } from "@/components/ui/field"
import { InputGroup, InputGroupAddon, InputGroupInput } from "@/components/ui/input-group"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"
import type { OutputType } from "@/lib/types"
import { cn } from "@/lib/utils"

import { categoryOrder, categoryTitle, driverTitle } from "./sections"

const ALL = "all"

interface DriverStepProps {
  types: readonly OutputType[]
  configured: ReadonlySet<string>
  selected: string | null
  onSelect: (driver: string) => void
}

export function DriverStep({ types, configured, selected, onSelect }: DriverStepProps) {
  const [query, setQuery] = useState("")
  const [category, setCategory] = useState(ALL)
  const categories = useMemo(() => [...new Set(types.map((t) => t.category))].sort(categoryOrder), [types])
  const visible = useMemo(() => {
    const q = query.trim().toLowerCase()
    return types
      .filter((t) => category === ALL || t.category === category)
      .filter((t) => q === "" || t.name.includes(q) || driverTitle(t.name).toLowerCase().includes(q) || categoryTitle(t.category).toLowerCase().includes(q))
      .sort((a, b) => Number(configured.has(a.name)) - Number(configured.has(b.name)) || driverTitle(a.name).localeCompare(driverTitle(b.name)))
  }, [types, query, category, configured])

  return (
    <div className="flex flex-col gap-4">
      <InputGroup>
        <InputGroupAddon>
          <Search aria-hidden />
        </InputGroupAddon>
        <InputGroupInput value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search drivers" aria-label="Search drivers" autoFocus />
      </InputGroup>
      {/* Chips where they fit on a line or two, a select on phones. */}
      <ToggleGroup
        type="single"
        size="sm"
        variant="outline"
        spacing={2}
        value={category}
        onValueChange={(v) => setCategory(v || ALL)}
        className="hidden w-full flex-wrap sm:flex"
        aria-label="Category"
      >
        <ToggleGroupItem value={ALL}>All</ToggleGroupItem>
        {categories.map((c) => (
          <ToggleGroupItem key={c} value={c}>
            {categoryTitle(c)}
          </ToggleGroupItem>
        ))}
      </ToggleGroup>
      <Select value={category} onValueChange={setCategory}>
        <SelectTrigger className="w-full sm:hidden" aria-label="Category">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value={ALL}>All categories</SelectItem>
          {categories.map((c) => (
            <SelectItem key={c} value={c}>
              {categoryTitle(c)}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      {types.some((t) => t.event_source) && (
        <FieldDescription className="flex items-center gap-1.5 text-xs">
          <DatabaseZap className="size-3.5 shrink-0 text-brand" aria-hidden />
          An event source also stores events, so the Events page and the dashboard can read them (ui.event_source).
        </FieldDescription>
      )}
      {visible.length === 0 ? (
        <Empty className="border">
          <EmptyHeader>
            <EmptyTitle>No driver matches</EmptyTitle>
            <EmptyDescription>Try another name or category.</EmptyDescription>
          </EmptyHeader>
        </Empty>
      ) : (
        <ul className="grid grid-cols-1 gap-2 sm:grid-cols-2 xl:grid-cols-3" aria-label="Drivers">
          {visible.map((t) => {
            const isConfigured = configured.has(t.name)
            const isSelected = selected === t.name
            return (
              <li key={t.name}>
                <button
                  type="button"
                  disabled={isConfigured}
                  aria-pressed={isSelected}
                  onClick={() => onSelect(t.name)}
                  className={cn(
                    "group flex w-full items-center gap-3 rounded-lg border bg-background p-3 text-left transition-colors",
                    "hover:border-foreground/25 hover:bg-accent/50 focus-visible:outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50",
                    "disabled:cursor-not-allowed disabled:opacity-55 disabled:hover:border-border disabled:hover:bg-background",
                    isSelected && "border-brand bg-brand/5 ring-1 ring-brand",
                  )}
                >
                  <OutputTypeIcon driver={t.name} />
                  <span className="flex min-w-0 flex-1 flex-col gap-1">
                    <span className="truncate text-sm font-medium" title={driverTitle(t.name)}>
                      {driverTitle(t.name)}
                    </span>
                    <span className="flex flex-wrap items-center gap-1.5 text-xs text-muted-foreground">
                      {categoryTitle(t.category)}
                      {t.event_source && (
                        <Badge variant="outline" className="border-brand/40 font-normal text-brand">
                          <DatabaseZap aria-hidden /> Event source
                        </Badge>
                      )}
                      {isConfigured && (
                        <Badge variant="secondary" className="font-normal">
                          Configured
                        </Badge>
                      )}
                    </span>
                  </span>
                  {isSelected && <Check className="size-4 shrink-0 text-brand" aria-hidden />}
                </button>
              </li>
            )
          })}
        </ul>
      )}
    </div>
  )
}
