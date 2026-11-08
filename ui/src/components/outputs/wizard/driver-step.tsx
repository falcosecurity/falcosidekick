import { Check, Search } from "lucide-react"
import { useMemo, useState } from "react"

import { OutputTypeIcon } from "@/components/common/output-type-icon"
import { Badge } from "@/components/ui/badge"
import { Empty, EmptyDescription, EmptyHeader, EmptyTitle } from "@/components/ui/empty"
import { InputGroup, InputGroupAddon, InputGroupInput } from "@/components/ui/input-group"
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
      <ToggleGroup
        type="single"
        size="sm"
        variant="outline"
        spacing={2}
        value={category}
        onValueChange={(v) => setCategory(v || ALL)}
        className="flex w-full flex-wrap"
        aria-label="Category"
      >
        <ToggleGroupItem value={ALL}>All</ToggleGroupItem>
        {categories.map((c) => (
          <ToggleGroupItem key={c} value={c}>
            {categoryTitle(c)}
          </ToggleGroupItem>
        ))}
      </ToggleGroup>
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
                  <span className="flex min-w-0 flex-1 flex-col">
                    <span className="truncate text-sm font-medium">{driverTitle(t.name)}</span>
                    <span className="truncate text-xs text-muted-foreground">{categoryTitle(t.category)}</span>
                  </span>
                  {isConfigured ? (
                    <Badge variant="secondary" className="shrink-0 font-normal">Configured</Badge>
                  ) : isSelected ? (
                    <Check className="size-4 shrink-0 text-brand" aria-hidden />
                  ) : null}
                </button>
              </li>
            )
          })}
        </ul>
      )}
    </div>
  )
}
