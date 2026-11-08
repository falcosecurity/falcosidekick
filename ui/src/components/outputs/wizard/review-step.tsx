import { FileKey2, KeyRound, Minus } from "lucide-react"

import { OutputTypeIcon } from "@/components/common/output-type-icon"
import { Item, ItemContent, ItemDescription, ItemMedia, ItemTitle } from "@/components/ui/item"
import type { SchemaField } from "@/lib/types"

import { isSecretString } from "./form-model"
import { driverTitle } from "./sections"

export interface ReviewRow {
  path: string
  label: string
  display: string
  kind: "value" | "secret-file" | "secret-value" | "cleared"
}

function labelFor(fields: readonly SchemaField[], path: string): { label: string; secret: boolean } {
  const field = fields.find((f) => f.name === path) ?? fields.find((f) => `${f.name}_file` === path)
  if (field) return { label: field.label, secret: isSecretString(field) }
  const parent = fields.find((f) => path.startsWith(`${f.name}.`))
  return { label: parent ? `${parent.label} · ${path.slice(parent.name.length + 1)}` : path, secret: false }
}

function render(value: unknown): string {
  if (Array.isArray(value)) return value.join(", ")
  if (value !== null && typeof value === "object") {
    return Object.entries(value)
      .filter(([, v]) => v !== null)
      .map(([k, v]) => `${k}: ${render(v)}`)
      .join("; ")
  }
  return String(value)
}

/** Flattens the patch into one row per field, in schema order; map fields stay one row per entry. */
export function reviewRows(fields: readonly SchemaField[], patch: Record<string, unknown>): ReviewRow[] {
  const rows: ReviewRow[] = []
  const walk = (value: unknown, path: string) => {
    const known = fields.some((f) => f.name === path || `${f.name}_file` === path)
    const mapField = fields.find((f) => f.type === "map" && f.name === path)
    if (mapField && value !== null && typeof value === "object") {
      for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
        const secret = entry !== null && typeof entry === "object" && Array.isArray((entry as Record<string, unknown>).secrets)
        rows.push({
          path: `${path}.${key}`,
          label: `${mapField.label} · ${key}`,
          display: entry === null ? "Removed" : secret ? "Hidden value" : render(entry),
          kind: entry === null ? "cleared" : secret ? "secret-value" : "value",
        })
      }
      return
    }
    if (!known && value !== null && typeof value === "object" && !Array.isArray(value)) {
      for (const [key, child] of Object.entries(value as Record<string, unknown>)) walk(child, path ? `${path}.${key}` : key)
      return
    }
    const { label, secret } = labelFor(fields, path)
    if (value === null) rows.push({ path, label, display: "Cleared, back to the default", kind: "cleared" })
    else if (path.endsWith("_file") && fields.some((f) => `${f.name}_file` === path)) rows.push({ path, label, display: String(value), kind: "secret-file" })
    else if (secret) rows.push({ path, label, display: "Hidden value", kind: "secret-value" })
    else rows.push({ path, label, display: render(value), kind: "value" })
  }
  walk(patch, "")
  const order = (p: string) => {
    const i = fields.findIndex((f) => p === f.name || p === `${f.name}_file` || p.startsWith(`${f.name}.`))
    return i === -1 ? fields.length : i
  }
  return rows.sort((a, b) => order(a.path) - order(b.path))
}

const ICON = {
  value: null,
  "secret-file": <FileKey2 className="size-4" aria-hidden />,
  "secret-value": <KeyRound className="size-4" aria-hidden />,
  cleared: <Minus className="size-4" aria-hidden />,
}

export function ReviewStep({ driver, editing, rows }: { driver: string; editing: boolean; rows: ReviewRow[] }) {
  return (
    <div className="flex flex-col gap-4">
      <Item variant="outline" className="bg-background">
        <ItemMedia>
          <OutputTypeIcon driver={driver} />
        </ItemMedia>
        <ItemContent>
          <ItemTitle>{driverTitle(driver)}</ItemTitle>
          <ItemDescription>
            {editing ? "Only the changes below are sent; everything else stays as stored." : "Created with the values below; every other field uses its default."}
          </ItemDescription>
        </ItemContent>
      </Item>
      {rows.length === 0 ? (
        <p className="rounded-lg border border-dashed p-6 text-center text-sm text-muted-foreground">Nothing changed.</p>
      ) : (
        <dl className="divide-y rounded-lg border bg-background">
          {rows.map((row) => (
            <div key={row.path} className="grid gap-1 px-4 py-2.5 text-sm sm:grid-cols-[minmax(0,14rem)_1fr] sm:gap-4">
              <dt className="text-muted-foreground">{row.label}</dt>
              <dd className={row.kind === "cleared" ? "flex items-center gap-1.5 text-muted-foreground" : "flex min-w-0 items-center gap-1.5"}>
                {ICON[row.kind]}
                <span className={row.kind === "secret-file" || row.kind === "value" ? "font-mono text-xs [overflow-wrap:anywhere]" : ""}>{row.display}</span>
              </dd>
            </div>
          ))}
        </dl>
      )}
    </div>
  )
}
