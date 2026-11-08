import { KeyRound, Plus, RotateCcw, Trash2 } from "lucide-react"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Field, FieldContent, FieldDescription, FieldError, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Switch } from "@/components/ui/switch"
import { Textarea } from "@/components/ui/textarea"
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"
import type { SchemaField } from "@/lib/types"

import { FilePathInput } from "./file-path-input"
import { ENTRY_KINDS, newRow, type EntryKind, type FieldValue, type MapRow, type SecretState } from "./form-model"
import { fieldHint } from "./sections"

const DEFAULT_ENUM = "__default__"

const ENTRY_LABEL: Record<EntryKind, string> = { values: "Value", secrets: "Secret value", files: "Secret file" }

interface FieldControlProps {
  field: SchemaField
  value: FieldValue
  onChange: (value: FieldValue) => void
  error?: string
  /** Inline secrets are refused by the database: secrets are files only. */
  filesOnly: boolean
}

function inputId(field: SchemaField): string {
  return `field-${field.name.replace(/[^\w-]/g, "-")}`
}

export function FieldControl({ field, value, onChange, error, filesOnly }: FieldControlProps) {
  const id = inputId(field)
  const hint = fieldHint(field)
  const describedBy = [hint && `${id}-hint`, error && `${id}-error`].filter(Boolean).join(" ") || undefined
  const label = (
    <FieldLabel htmlFor={id}>
      {field.label}
      {field.required && <span className="text-destructive" aria-hidden>*</span>}
      {field.required && <span className="sr-only">(required)</span>}
    </FieldLabel>
  )
  const footer = (
    <>
      {hint && <FieldDescription id={`${id}-hint`}>{hint}</FieldDescription>}
      {error && <FieldError id={`${id}-error`}>{error}</FieldError>}
    </>
  )

  if (value.kind === "bool") {
    const fallback = field.default === true
    return (
      <Field orientation="horizontal" data-invalid={error ? true : undefined}>
        <FieldContent>
          {label}
          <FieldDescription id={`${id}-hint`}>
            {value.value === null ? `Default: ${fallback ? "on" : "off"}` : value.value === fallback ? "Same as the default" : "Changed from the default"}
          </FieldDescription>
        </FieldContent>
        {value.value !== null && (
          <Button type="button" variant="ghost" size="icon" className="size-7" onClick={() => onChange({ kind: "bool", value: null })} aria-label={`Reset ${field.label} to the default`}>
            <RotateCcw className="size-3.5" aria-hidden />
          </Button>
        )}
        <Switch id={id} checked={value.value ?? fallback} onCheckedChange={(checked) => onChange({ kind: "bool", value: checked })} aria-describedby={`${id}-hint`} />
      </Field>
    )
  }

  if (value.kind === "secret") {
    return (
      <Field data-invalid={error ? true : undefined}>
        {label}
        <SecretControl id={id} secret={value.secret} filesOnly={filesOnly} invalid={!!error} describedBy={describedBy} onChange={(secret) => onChange({ kind: "secret", secret })} />
        {error && <FieldError id={`${id}-error`}>{error}</FieldError>}
      </Field>
    )
  }

  if (value.kind === "map") {
    return (
      <Field data-invalid={error ? true : undefined}>
        <FieldLabel htmlFor={`${id}-add`}>{field.label}</FieldLabel>
        <MapEditor id={id} field={field} rows={value.rows} filesOnly={filesOnly} onChange={(rows) => onChange({ kind: "map", rows })} />
        {error && <FieldError id={`${id}-error`}>{error}</FieldError>}
      </Field>
    )
  }

  const text = value.text
  const set = (next: string) => onChange({ kind: "text", text: next })
  const placeholder = field.default !== undefined && field.default !== "" ? String(field.default) : undefined
  let control
  if (field.type === "enum" && field.values) {
    control = (
      <Select value={text === "" ? DEFAULT_ENUM : text} onValueChange={(v) => set(v === DEFAULT_ENUM ? "" : v)}>
        <SelectTrigger id={id} className="w-full" aria-invalid={error ? true : undefined} aria-describedby={describedBy}>
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {!field.required && (
            <SelectItem value={DEFAULT_ENUM}>
              <span className="text-muted-foreground">{placeholder ? `Default (${placeholder})` : "Not set"}</span>
            </SelectItem>
          )}
          {field.values.map((v) => (
            <SelectItem key={v} value={v}>
              {v}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    )
  } else if (field.type === "string[]") {
    control = (
      <Textarea id={id} value={text} onChange={(e) => set(e.target.value)} placeholder={field.file ? "One absolute path per line" : "One per line"} rows={3} className="font-mono text-xs" aria-invalid={error ? true : undefined} aria-describedby={describedBy} />
    )
  } else if (field.file) {
    control = <FilePathInput id={id} value={text} onChange={set} invalid={!!error} aria-describedby={describedBy} />
  } else {
    control = (
      <Input
        id={id}
        value={text}
        onChange={(e) => set(e.target.value)}
        placeholder={placeholder}
        inputMode={field.type === "int" ? "numeric" : field.type === "float" ? "decimal" : undefined}
        aria-invalid={error ? true : undefined}
        aria-describedby={describedBy}
        autoComplete="off"
        spellCheck={false}
      />
    )
  }
  return (
    <Field data-invalid={error ? true : undefined}>
      {label}
      {control}
      {footer}
    </Field>
  )
}

function SecretControl({
  id,
  secret,
  filesOnly,
  invalid,
  describedBy,
  onChange,
}: {
  id: string
  secret: SecretState
  filesOnly: boolean
  invalid: boolean
  describedBy?: string
  onChange: (secret: SecretState) => void
}) {
  if (secret.mode === "keep") {
    return (
      <div className="flex flex-wrap items-center gap-2 rounded-md border border-dashed px-3 py-2 text-sm">
        <KeyRound className="size-4 text-muted-foreground" aria-hidden />
        <span>Stored, hidden</span>
        <span className="ml-auto flex gap-1">
          <Button id={id} type="button" variant="outline" size="sm" onClick={() => onChange({ ...secret, mode: "file" })}>
            Replace
          </Button>
          <Button type="button" variant="ghost" size="sm" onClick={() => onChange({ ...secret, mode: "none" })}>
            Remove
          </Button>
        </span>
      </div>
    )
  }
  const mode = secret.mode === "none" ? (filesOnly ? "file" : "value") : secret.mode
  return (
    <div className="flex flex-col gap-2">
      {!filesOnly && (
        <ToggleGroup type="single" variant="outline" size="sm" value={mode} onValueChange={(v) => v && onChange({ ...secret, mode: v as "file" | "value" })} aria-label="Secret source">
          <ToggleGroupItem value="file">From a file</ToggleGroupItem>
          <ToggleGroupItem value="value">Value</ToggleGroupItem>
        </ToggleGroup>
      )}
      {mode === "file" ? (
        <FilePathInput id={id} value={secret.file} invalid={invalid} aria-describedby={describedBy} onChange={(file) => onChange({ ...secret, mode: file === "" ? "none" : "file", file })} />
      ) : (
        <Input id={id} type="password" value={secret.value} autoComplete="new-password" aria-invalid={invalid || undefined} aria-describedby={describedBy} onChange={(e) => onChange({ ...secret, mode: e.target.value === "" ? "none" : "value", value: e.target.value })} />
      )}
      <p className="text-xs text-muted-foreground">
        {filesOnly
          ? "The database keeps only the path; Sidekick reads the file and follows its changes."
          : mode === "value"
            ? "Kept in memory only and lost on restart."
            : "Sidekick reads the file and follows its changes."}
        {secret.stored && (
          <Button type="button" variant="link" size="sm" className="h-auto px-1 py-0 text-xs" onClick={() => onChange({ ...secret, mode: "keep", file: "", value: "" })}>
            Keep the stored one
          </Button>
        )}
      </p>
    </div>
  )
}

function MapEditor({
  id,
  field,
  rows,
  filesOnly,
  onChange,
}: {
  id: string
  field: SchemaField
  rows: MapRow[]
  filesOnly: boolean
  onChange: (rows: MapRow[]) => void
}) {
  const entryMap = (field.entry_fields?.length ?? 0) > 0
  const kinds = ENTRY_KINDS.filter((k) => !(filesOnly && k === "secrets"))
  const update = (rowId: number, change: Partial<MapRow>) =>
    onChange(rows.map((r) => (r.id === rowId ? { ...r, ...change, edited: true } : r)))
  return (
    <div className="flex flex-col gap-2">
      {rows.length > 0 && (
        <ul className="flex flex-col gap-2">
          {rows.map((row) => {
            const keptSecret = row.kind === "secrets" && row.stored && !row.edited
            return (
              <li key={row.id} className="grid grid-cols-[minmax(0,1fr)_auto] gap-2 rounded-md border p-2 sm:grid-cols-[minmax(0,10rem)_auto_minmax(0,1fr)_auto] sm:items-center sm:border-0 sm:p-0">
                <Input value={row.key} onChange={(e) => update(row.id, { key: e.target.value })} placeholder="Name" aria-label={`${field.label} name`} className="font-mono text-xs" autoComplete="off" />
                {entryMap ? (
                  <Select value={row.kind} onValueChange={(v) => update(row.id, { kind: v as EntryKind, text: "" })}>
                    <SelectTrigger className="w-36" aria-label={`${row.key || "Entry"} source`}>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {(kinds.includes(row.kind) ? kinds : [...kinds, row.kind]).map((k) => (
                        <SelectItem key={k} value={k}>
                          {ENTRY_LABEL[k]}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                ) : (
                  <span className="hidden sm:block" />
                )}
                <div className="col-span-2 sm:col-span-1">
                  {keptSecret ? (
                    <Badge variant="outline" className="gap-1 font-normal">
                      <KeyRound className="size-3" aria-hidden /> Stored, hidden
                    </Badge>
                  ) : row.kind === "files" ? (
                    <FilePathInput
                      id={`${id}-row-${row.id}`}
                      value={row.text}
                      onChange={(text) => update(row.id, { text })}
                      aria-label={`${row.key || "Entry"} file`}
                    />
                  ) : (
                    <Input type={row.kind === "secrets" ? "password" : "text"} value={row.text} onChange={(e) => update(row.id, { text: e.target.value })} placeholder="Value" aria-label={`${row.key || "Entry"} value`} autoComplete="off" />
                  )}
                </div>
                <Button type="button" variant="ghost" size="icon" className="row-start-1 col-start-2 size-8 sm:row-auto sm:col-auto" onClick={() => onChange(rows.filter((r) => r.id !== row.id))} aria-label={`Remove ${row.key || "entry"}`}>
                  <Trash2 className="size-4" aria-hidden />
                </Button>
              </li>
            )
          })}
        </ul>
      )}
      <Button id={`${id}-add`} type="button" variant="outline" size="sm" className="w-fit" onClick={() => onChange([...rows, newRow({ kind: "values" })])}>
        <Plus className="size-3.5" aria-hidden /> Add {field.label.toLowerCase().replace(/s$/, "")}
      </Button>
    </div>
  )
}
