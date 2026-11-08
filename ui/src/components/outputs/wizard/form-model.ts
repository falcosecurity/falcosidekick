import type { OutputConfigEntry, SchemaField } from "@/lib/types"

// The wizard keeps every field as text the user edits, then turns it into the PUT patch. The API
// merges the patch into the stored config: a key set to null is cleared, a key left out is kept.

export type SecretMode = "keep" | "file" | "value" | "none"
export type EntryKind = "values" | "secrets" | "files"

export interface SecretState {
  mode: SecretMode
  file: string
  value: string
  /** The stored output has this secret, as a file or a value. */
  stored: boolean
}

export interface MapRow {
  id: number
  key: string
  kind: EntryKind
  text: string
  /** Set when the row comes from the stored output; a stored secret entry is kept unless edited. */
  stored: boolean
  edited: boolean
}

export type FieldValue =
  | { kind: "text"; text: string }
  | { kind: "bool"; value: boolean | null }
  | { kind: "secret"; secret: SecretState }
  | { kind: "map"; rows: MapRow[] }

export type FormState = Record<string, FieldValue>

export const ENTRY_KINDS: readonly EntryKind[] = ["values", "secrets", "files"]

export function isSecretString(field: SchemaField): boolean {
  return field.secret === true && field.type === "string"
}

function isEntryMap(field: SchemaField): boolean {
  return field.type === "map" && (field.entry_fields?.length ?? 0) > 0
}

function getPath(cfg: Record<string, unknown> | null | undefined, path: string): unknown {
  let current: unknown = cfg
  for (const part of path.split(".")) {
    if (current === null || typeof current !== "object") return undefined
    current = (current as Record<string, unknown>)[part]
  }
  return current
}

function setPath(target: Record<string, unknown>, path: string, value: unknown): void {
  const parts = path.split(".")
  let current = target
  for (const part of parts.slice(0, -1)) {
    const next = current[part]
    if (next === null || typeof next !== "object") current[part] = {}
    current = current[part] as Record<string, unknown>
  }
  current[parts[parts.length - 1]!] = value
}

function siblingPath(path: string, leaf: string): string {
  const parts = path.split(".")
  parts[parts.length - 1] = leaf
  return parts.join(".")
}

function leafOf(path: string): string {
  return path.split(".").pop()!
}

function textOf(value: unknown, field: SchemaField): string {
  if (value === undefined || value === null) return ""
  if (field.type === "string[]" && Array.isArray(value)) return value.join("\n")
  return String(value)
}

let nextRowId = 1
export function newRow(partial: Partial<MapRow> = {}): MapRow {
  return { id: nextRowId++, key: "", kind: "values", text: "", stored: false, edited: false, ...partial }
}

function rowsOf(value: unknown, field: SchemaField): MapRow[] {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return []
  const rows: MapRow[] = []
  for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
    if (!isEntryMap(field)) {
      rows.push(newRow({ key, text: textOf(entry, field), stored: true }))
      continue
    }
    const object = (entry ?? {}) as Record<string, unknown>
    for (const kind of ENTRY_KINDS) {
      const list = object[kind]
      if (!Array.isArray(list)) continue
      for (const item of list) {
        // Secret values come back masked; the row keeps the stored value unless edited.
        rows.push(newRow({ key, kind, text: kind === "secrets" ? "" : String(item), stored: true }))
      }
    }
  }
  return rows
}

/** secretPointer is the JSON pointer the API uses in secret_fields for a field path. */
function secretPointer(path: string): string {
  return "/" + path.split(".").join("/")
}

/** Builds the form for a new output, or from the stored output when editing. */
export function initialState(fields: readonly SchemaField[], entry?: OutputConfigEntry | null): FormState {
  const cfg = entry?.config ?? null
  const state: FormState = {}
  for (const field of fields) {
    if (isSecretString(field)) {
      const file = getPath(cfg, siblingPath(field.name, `${leafOf(field.name)}_file`))
      const stored = typeof file === "string" || entry?.secret_fields?.[secretPointer(field.name)] === true
      state[field.name] = {
        kind: "secret",
        secret: {
          mode: typeof file === "string" ? "file" : stored ? "keep" : "none",
          file: typeof file === "string" ? file : "",
          value: "",
          stored,
        },
      }
    } else if (field.type === "bool") {
      const value = getPath(cfg, field.name)
      state[field.name] = { kind: "bool", value: typeof value === "boolean" ? value : null }
    } else if (field.type === "map") {
      state[field.name] = { kind: "map", rows: rowsOf(getPath(cfg, field.name), field) }
    } else {
      state[field.name] = { kind: "text", text: textOf(getPath(cfg, field.name), field) }
    }
  }
  return state
}

export interface ValidationOptions {
  /** The database refuses inline secrets: a secret can only be a file. */
  filesOnly: boolean
}

/** Field name to message; empty when the form can be sent. */
export function validate(
  fields: readonly SchemaField[],
  state: FormState,
  options: ValidationOptions,
): Record<string, string> {
  const errors: Record<string, string> = {}
  for (const field of fields) {
    const value = state[field.name]
    if (!value) continue
    if (value.kind === "text") {
      const text = value.text.trim()
      if (field.required && text === "") errors[field.name] = "Required"
      else if (text !== "" && field.type === "int" && !/^-?\d+$/.test(text)) errors[field.name] = "Must be a whole number"
      else if (text !== "" && field.type === "float" && Number.isNaN(Number(text))) errors[field.name] = "Must be a number"
      else if (text !== "" && field.type === "enum" && field.values && !field.values.includes(text)) {
        errors[field.name] = `Must be one of ${field.values.join(", ")}`
      }
    } else if (value.kind === "secret") {
      const s = value.secret
      const empty = s.mode === "none" || (s.mode === "file" && s.file.trim() === "") || (s.mode === "value" && s.value === "")
      if (field.required && empty) errors[field.name] = "Required"
      else if (s.mode === "file" && s.file.trim() !== "" && !s.file.trim().startsWith("/")) {
        errors[field.name] = "Must be an absolute path"
      } else if (s.mode === "value" && options.filesOnly) {
        errors[field.name] = "This database keeps only secret files: pick a file"
      }
    } else if (value.kind === "map") {
      const keys = new Set<string>()
      for (const row of value.rows) {
        const key = row.key.trim()
        if (key === "") {
          errors[field.name] = "Every entry needs a name"
          break
        }
        if (!isEntryMap(field) && keys.has(key)) {
          errors[field.name] = `"${key}" appears twice`
          break
        }
        keys.add(key)
        if (row.kind === "secrets" && options.filesOnly && (row.edited || !row.stored)) {
          errors[field.name] = `"${key}": this database keeps only secret files`
          break
        }
        if (row.kind === "files" && row.text.trim() !== "" && !row.text.trim().startsWith("/")) {
          errors[field.name] = `"${key}": must be an absolute path`
          break
        }
      }
    }
  }
  return errors
}

function parsedText(field: SchemaField, text: string): unknown {
  const trimmed = text.trim()
  if (trimmed === "") return undefined
  if (field.type === "int") return Number.parseInt(trimmed, 10)
  if (field.type === "float") return Number(trimmed)
  if (field.type === "string[]") {
    return trimmed
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean)
  }
  return field.secret ? text : trimmed
}

function sameValue(a: unknown, b: unknown): boolean {
  return JSON.stringify(a ?? null) === JSON.stringify(b ?? null)
}

function entryObject(rows: MapRow[], field: SchemaField): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const row of rows) {
    const key = row.key.trim()
    if (!isEntryMap(field)) {
      out[key] = row.text
      continue
    }
    const entry = (out[key] ??= {}) as Record<string, string[]>
    ;(entry[row.kind] ??= []).push(row.text)
  }
  return out
}

/**
 * Builds the PUT patch. A new output sends what is set; an edit sends only what changed, with null
 * for what was cleared, and leaves stored secrets out unless replaced.
 */
export function buildPatch(
  fields: readonly SchemaField[],
  state: FormState,
  stored?: OutputConfigEntry | null,
): Record<string, unknown> {
  const cfg = stored?.config ?? null
  const editing = stored != null
  const patch: Record<string, unknown> = {}
  for (const field of fields) {
    const value = state[field.name]
    if (!value) continue
    // A cleared field is stored as null by the merge, so null reads as unset.
    const before = getPath(cfg, field.name) ?? undefined
    if (value.kind === "text") {
      const next = parsedText(field, value.text)
      if (next !== undefined && !sameValue(next, before)) setPath(patch, field.name, next)
      else if (next === undefined && editing && before !== undefined) setPath(patch, field.name, null)
    } else if (value.kind === "bool") {
      if (value.value !== null && value.value !== before) setPath(patch, field.name, value.value)
      else if (value.value === null && editing && before !== undefined) setPath(patch, field.name, null)
    } else if (value.kind === "secret") {
      const s = value.secret
      const filePath = siblingPath(field.name, `${leafOf(field.name)}_file`)
      const storedFile = getPath(cfg, filePath)
      if (s.mode === "file" && s.file.trim() !== "" && s.file.trim() !== storedFile) setPath(patch, filePath, s.file.trim())
      else if (s.mode === "value" && s.value !== "") setPath(patch, field.name, s.value)
      else if (s.mode === "none" && editing && s.stored) {
        setPath(patch, field.name, null)
        setPath(patch, filePath, null)
      }
    } else {
      const rows = value.rows.filter((row) => !(row.stored && !row.edited && row.kind === "secrets"))
      const keptSecretKeys = new Set(
        value.rows.filter((row) => row.stored && !row.edited && row.kind === "secrets").map((row) => row.key.trim()),
      )
      const next = entryObject(rows, field)
      const previous = (before ?? {}) as Record<string, unknown>
      const changes: Record<string, unknown> = {}
      for (const [key, entry] of Object.entries(next)) {
        if (keptSecretKeys.has(key)) continue
        const full = isEntryMap(field)
          ? Object.fromEntries(ENTRY_KINDS.map((kind) => [kind, (entry as Record<string, unknown>)[kind] ?? null]))
          : entry
        if (!sameValue(entry, previous[key])) changes[key] = editing ? full : entry
      }
      if (editing) {
        for (const key of Object.keys(previous)) {
          if (!(key in next) && !keptSecretKeys.has(key)) changes[key] = null
        }
      }
      if (Object.keys(changes).length > 0) setPath(patch, field.name, changes)
    }
  }
  return patch
}

/**
 * Finds the field a backend 400 message names. Messages start with the location: "password_file: ...",
 * "tls.ca_file: ...", `headers["X"].files[0]: ...`.
 */
export function fieldOfError(fields: readonly SchemaField[], message: string): string | null {
  const location = message.split(":")[0]?.trim() ?? ""
  let best: string | null = null
  for (const field of fields) {
    const names = [field.name]
    if (isSecretString(field)) names.push(`${field.name}_file`)
    for (const name of names) {
      const matches = location === name || location.startsWith(`${name}[`) || location.startsWith(`${name}.`)
      if (matches && (best === null || field.name.length > best.length)) best = field.name
    }
  }
  return best
}

/** Counts the fields that hold a value, for the section headers. */
export function countSet(names: readonly string[], state: FormState): number {
  return names.filter((name) => {
    const value = state[name]
    if (!value) return false
    if (value.kind === "text") return value.text.trim() !== ""
    if (value.kind === "bool") return value.value !== null
    if (value.kind === "secret") return value.secret.mode !== "none"
    return value.rows.length > 0
  }).length
}
