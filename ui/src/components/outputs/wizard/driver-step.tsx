import { Check, CircleCheck, DatabaseZap, Search } from "lucide-react"
import { useMemo, useState } from "react"

import { OutputTypeIcon } from "@/components/common/output-type-icon"
import { Empty, EmptyDescription, EmptyHeader, EmptyTitle } from "@/components/ui/empty"
import { FieldDescription } from "@/components/ui/field"
import { InputGroup, InputGroupAddon, InputGroupInput } from "@/components/ui/input-group"
import { ScrollArea } from "@/components/ui/scroll-area"
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
    // Search and categories stay fixed; only the drivers scroll, in their own area.
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="flex shrink-0 flex-col gap-3 border-b px-6 pt-5 pb-4">
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
          Event source: the driver also stores events, so the Events page and the dashboard can read them (ui.event_source).
        </FieldDescription>
      )}
      </div>
      <ScrollArea className="min-h-0 flex-1">
      {/* Padding keeps tile borders and focus rings inside the scroll area. */}
      <div className="px-6 py-4">
      {visible.length === 0 ? (
        <Empty className="border">
          <EmptyHeader>
            <EmptyTitle>No driver matches</EmptyTitle>
            <EmptyDescription>Try another name or category.</EmptyDescription>
          </EmptyHeader>
        </Empty>
      ) : (
        <ul className="grid auto-rows-fr grid-cols-1 gap-2 sm:grid-cols-2 xl:grid-cols-3" aria-label="Drivers">
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
                    "group flex h-full w-full items-center gap-3 rounded-lg border bg-background p-3 text-left transition-colors",
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
                    <span className="truncate text-xs text-muted-foreground">{categoryTitle(t.category)}</span>
                  </span>
                  <span className="flex shrink-0 items-center gap-2 text-muted-foreground">
                    {t.event_source && (
                      <span title="Event source">
                        <DatabaseZap className="size-4 text-brand" aria-hidden />
                        <span className="sr-only">Event source</span>
                      </span>
                    )}
                    {isConfigured ? (
                      <span title="Already configured">
                        <CircleCheck className="size-4" aria-hidden />
                        <span className="sr-only">Configured</span>
                      </span>
                    ) : (
                      isSelected && <Check className="size-4 text-brand" aria-hidden />
                    )}
                  </span>
                </button>
              </li>
            )
          })}
        </ul>
      )}
      </div>
      </ScrollArea>
    </div>
  )
}
