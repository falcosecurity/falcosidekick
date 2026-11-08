import { Check, ChevronDown, X } from "lucide-react"
import { useMemo, useState } from "react"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
} from "@/components/ui/command"
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover"
import { cn } from "@/lib/utils"

export interface MultiSelectOption {
  value: string
  label: string
  hint?: string
}

interface MultiSelectFilterProps {
  label: string
  placeholder?: string
  options: readonly MultiSelectOption[]
  values: readonly string[]
  onChange: (next: string[]) => void
  className?: string
  allowCustom?: boolean
  align?: "start" | "end" | "center"
}

export function MultiSelectFilter({
  label,
  placeholder,
  options,
  values,
  onChange,
  className,
  allowCustom = false,
  align = "start",
}: MultiSelectFilterProps) {
  const [open, setOpen] = useState(false)
  const [search, setSearch] = useState("")

  const selected = useMemo(() => new Set(values), [values])

  const { selectedOptions, unselectedOptions, customOption } = useMemo(() => {
    const customValue = search.trim()
    const q = customValue.toLowerCase()
    const matches = (o: MultiSelectOption) =>
      q === "" || o.label.toLowerCase().includes(q) || o.value.toLowerCase().includes(q)

    const selectedVisible: MultiSelectOption[] = []
    for (const v of values) {
      const known = options.find((o) => o.value === v)
      const opt = known ?? { value: v, label: v }
      if (matches(opt)) selectedVisible.push(opt)
    }

    const unselected = options.filter((o) => !selected.has(o.value) && matches(o))

    let custom: MultiSelectOption | undefined
    if (allowCustom && customValue && !options.some((o) => o.value === customValue) && !selected.has(customValue)) {
      custom = { value: customValue, label: customValue, hint: "add custom" }
    }

    return { selectedOptions: selectedVisible, unselectedOptions: unselected, customOption: custom }
  }, [options, values, search, allowCustom, selected])

  function toggle(value: string) {
    const next = new Set(selected)
    if (next.has(value)) next.delete(value)
    else next.add(value)
    onChange(Array.from(next))
  }

  function clear() {
    onChange([])
  }

  const count = values.length
  const summary =
    count === 0
      ? placeholder ?? label
      : count === 1
        ? (options.find((o) => o.value === values[0])?.label ?? values[0])
        : `${count} selected`

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          variant="outline"
          size="sm"
          className={cn(
            "h-9 min-w-36 justify-between font-normal",
            count === 0 && "text-muted-foreground",
            className,
          )}
          aria-label={label}
        >
          <span className="flex items-center gap-2 truncate">
            <span className="truncate">{summary}</span>
            {count > 1 && (
              <Badge variant="secondary" className="h-5 px-1.5 text-[10px]">
                {count}
              </Badge>
            )}
          </span>
          <ChevronDown className="size-3.5 shrink-0 opacity-50" aria-hidden />
        </Button>
      </PopoverTrigger>
      <PopoverContent className="w-72 p-0" align={align}>
        <Command label={label} shouldFilter={false}>
          <CommandInput
            placeholder={`Search ${label.toLowerCase()}…`}
            value={search}
            onValueChange={setSearch}
          />
          {count > 0 && (
            <div className="flex items-center justify-between border-b px-2 py-1.5">
              <span className="text-[11px] text-muted-foreground">
                {count} selected
              </span>
              <Button
                variant="ghost"
                size="sm"
                className="h-6 px-2 text-[11px]"
                onClick={clear}
              >
                <X className="mr-1 size-3" aria-hidden />
                Clear
              </Button>
            </div>
          )}
          <CommandList>
            <CommandEmpty>No matches.</CommandEmpty>
            {selectedOptions.length > 0 && (
              <CommandGroup heading="Selected">
                {selectedOptions.map((opt) => (
                  <FilterItem key={`sel-${opt.value}`} option={opt} active onSelect={toggle} />
                ))}
              </CommandGroup>
            )}
            {selectedOptions.length > 0 && (unselectedOptions.length > 0 || customOption) && (
              <CommandSeparator />
            )}
            {(unselectedOptions.length > 0 || customOption) && (
              <CommandGroup heading={selectedOptions.length > 0 ? "Available" : undefined}>
                {unselectedOptions.map((opt) => (
                  <FilterItem key={opt.value} option={opt} active={false} onSelect={toggle} />
                ))}
                {customOption && (
                  <FilterItem
                    key={`custom-${customOption.value}`}
                    option={customOption}
                    active={false}
                    onSelect={toggle}
                  />
                )}
              </CommandGroup>
            )}
          </CommandList>
        </Command>
      </PopoverContent>
    </Popover>
  )
}

function FilterItem({
  option,
  active,
  onSelect,
}: {
  option: MultiSelectOption
  active: boolean
  onSelect: (value: string) => void
}) {
  return (
    <CommandItem
      value={option.value}
      onSelect={() => onSelect(option.value)}
      className="flex items-center justify-between gap-2"
    >
      <span className="flex min-w-0 items-center gap-2">
        <span
          className={cn(
            "flex size-4 items-center justify-center rounded-sm border",
            active ? "border-brand bg-brand text-brand-foreground" : "border-border",
          )}
          aria-hidden
        >
          {active && <Check className="size-3" />}
        </span>
        <span className="truncate">{option.label}</span>
      </span>
      {option.hint && (
        <span className="text-[10px] text-muted-foreground">{option.hint}</span>
      )}
    </CommandItem>
  )
}
