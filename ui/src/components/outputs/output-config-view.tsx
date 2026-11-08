import { ChevronsDownUp, ChevronsUpDown, FileKey2, Info, KeyRound } from "lucide-react"
import { useMemo, useState, type ReactNode } from "react"

import { SectionHeading } from "@/components/common/section-heading"
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import type { OutputConfigEntry, SchemaField } from "@/lib/types"

import { getPath, isSecretString } from "./wizard/form-model"
import { sectionsFor } from "./wizard/sections"

type Mode = "set" | "all"

interface FieldView {
  field: SchemaField
  /** Set in the stored config, as opposed to the type's default. */
  set: boolean
  value: ReactNode
}

function text(value: unknown): string {
  if (Array.isArray(value)) return value.join(", ")
  if (value !== null && typeof value === "object") return JSON.stringify(value)
  return String(value)
}

function secretPointer(path: string): string {
  return "/" + path.split(".").join("/")
}

function fileName(path: string): string {
  return path.split(".").slice(0, -1).concat(`${path.split(".").pop()}_file`).join(".")
}

function Mono({ children }: { children: ReactNode }) {
  return <span className="font-mono text-xs [overflow-wrap:anywhere]">{children}</span>
}

function mapView(value: Record<string, unknown>, entry: OutputConfigEntry, path: string): ReactNode {
  return (
    <ul className="flex flex-col gap-1">
      {Object.entries(value).map(([key, item]) => {
        const object = (item ?? {}) as Record<string, unknown>
        const files = Array.isArray(object.files) ? (object.files as string[]) : []
        const values = Array.isArray(object.values) ? (object.values as string[]) : []
        const secret = entry.secret_fields?.[`${secretPointer(path)}/${key}/secrets`] === true || Array.isArray(object.secrets)
        return (
          <li key={key} className="flex flex-wrap items-center gap-x-2 gap-y-0.5">
            <Mono>{key}</Mono>
            <span className="text-muted-foreground" aria-hidden>→</span>
            {typeof item !== "object" || item === null ? (
              <Mono>{text(item)}</Mono>
            ) : (
              <>
                {values.length > 0 && <Mono>{values.join(", ")}</Mono>}
                {secret && <HiddenSecret />}
                {files.map((f) => (
                  <SecretFile key={f} path={f} />
                ))}
              </>
            )}
          </li>
        )
      })}
    </ul>
  )
}

function HiddenSecret() {
  return (
    <span className="inline-flex items-center gap-1 text-xs text-muted-foreground">
      <KeyRound className="size-3" aria-hidden /> stored, hidden
    </span>
  )
}

function SecretFile({ path }: { path: string }) {
  return (
    <span className="inline-flex min-w-0 items-center gap-1">
      <FileKey2 className="size-3 shrink-0 text-muted-foreground" aria-label="secret file" />
      <Mono>{path}</Mono>
    </span>
  )
}

/** Every field of the type with its stored value, or its default when unset. */
function fieldViews(fields: readonly SchemaField[], entry: OutputConfigEntry): FieldView[] {
  const cfg = entry.config ?? {}
  return fields.map((field) => {
    if (isSecretString(field)) {
      const file = getPath(cfg, fileName(field.name))
      if (typeof file === "string") return { field, set: true, value: <SecretFile path={file} /> }
      if (entry.secret_fields?.[secretPointer(field.name)]) return { field, set: true, value: <HiddenSecret /> }
      return { field, set: false, value: null }
    }
    const value = getPath(cfg, field.name) ?? undefined
    if (value !== undefined) {
      if (field.type === "map" && typeof value === "object" && value !== null) {
        return Object.keys(value).length > 0
          ? { field, set: true, value: mapView(value as Record<string, unknown>, entry, field.name) }
          : { field, set: false, value: null }
      }
      return { field, set: true, value: <Mono>{text(value)}</Mono> }
    }
    const fallback = field.default
    const hasDefault = fallback !== undefined && fallback !== null && fallback !== ""
    return { field, set: false, value: hasDefault ? <Mono>{text(fallback)}</Mono> : null }
  })
}

/** Read-only view of an output's configuration, in the wizard's sections, set values first. */
export function OutputConfigView({ entry, fields }: { entry: OutputConfigEntry; fields: readonly SchemaField[] }) {
  const [mode, setMode] = useState<Mode>("set")
  const views = useMemo(() => new Map(fieldViews(fields, entry).map((v) => [v.field.name, v])), [fields, entry])
  const sections = useMemo(() => sectionsFor(fields), [fields])
  const visible = sections
    .map((section) => ({
      ...section,
      views: section.fields.map((f) => views.get(f.name)!).filter((v) => mode === "all" || v.set),
      setCount: section.fields.filter((f) => views.get(f.name)?.set).length,
    }))
    .filter((s) => s.views.length > 0)
  const [open, setOpen] = useState<string[]>(() => sections.filter((s) => s.fields.some((f) => views.get(f.name)?.set)).map((s) => s.key))
  const allOpen = visible.length > 0 && visible.every((s) => open.includes(s.key))

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <SectionHeading level={3} className="text-sm normal-case tracking-normal text-foreground">
          Configuration
        </SectionHeading>
        <div className="flex items-center gap-1">
          <Button
            type="button"
            variant="ghost"
            size="sm"
            className="h-7 px-2 text-xs"
            disabled={visible.length === 0}
            onClick={() => setOpen(allOpen ? [] : visible.map((s) => s.key))}
          >
            {allOpen ? <ChevronsDownUp aria-hidden /> : <ChevronsUpDown aria-hidden />}
            {allOpen ? "Collapse all" : "Expand all"}
          </Button>
          <ToggleGroup type="single" variant="outline" size="sm" value={mode} onValueChange={(v) => v && setMode(v as Mode)} aria-label="Fields shown">
            <ToggleGroupItem value="set" className="px-2.5 text-xs">Set</ToggleGroupItem>
            <ToggleGroupItem value="all" className="px-2.5 text-xs">All fields</ToggleGroupItem>
          </ToggleGroup>
        </div>
      </div>
      {visible.length === 0 ? (
        <p className="rounded-lg border border-dashed px-3 py-4 text-sm text-muted-foreground">
          Nothing set: every field uses its default. Show all fields to see them.
        </p>
      ) : (
        <Accordion type="multiple" value={open} onValueChange={setOpen} className="overflow-hidden rounded-lg border bg-background">
          {visible.map((section) => (
            <AccordionItem key={section.key} value={section.key} className="px-3">
              <AccordionTrigger className="py-3 hover:no-underline">
                <span>{section.title}</span>
                <span className="ml-auto pr-2 text-xs font-normal tabular-nums text-muted-foreground">
                  {section.setCount > 0 ? `${section.setCount} set` : "defaults"}
                </span>
              </AccordionTrigger>
              <AccordionContent>
                {/* The panel width, not the window, decides whether label and value share a row. */}
                <dl className="@container flex flex-col divide-y">
                  {section.views.map(({ field, set, value }) => (
                    <div key={field.name} className="grid gap-1 py-2 text-sm @sm:grid-cols-[minmax(0,9rem)_1fr] @sm:gap-3">
                      <dt className="flex items-start gap-1 text-muted-foreground [overflow-wrap:anywhere]">
                        {field.label}
                        {field.description && (
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <Button type="button" variant="ghost" size="icon" className="size-5 shrink-0" aria-label={`About ${field.label}`}>
                                <Info className="size-3.5" aria-hidden />
                              </Button>
                            </TooltipTrigger>
                            <TooltipContent className="max-w-xs">{field.description}</TooltipContent>
                          </Tooltip>
                        )}
                      </dt>
                      <dd className={set ? "min-w-0" : "flex min-w-0 flex-wrap items-center gap-1.5 text-muted-foreground"}>
                        {value ?? <span aria-label="not set">—</span>}
                        {!set && value !== null && (
                          <Badge variant="outline" className="font-normal text-muted-foreground">default</Badge>
                        )}
                      </dd>
                    </div>
                  ))}
                </dl>
              </AccordionContent>
            </AccordionItem>
          ))}
        </Accordion>
      )}
    </div>
  )
}
