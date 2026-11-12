import type { FieldProblem } from "@/lib/api-error"
import { parseGoDuration } from "@/lib/format"
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

/** Reads a dotted schema path ("tls.ca_file") from a nested config. */
export function getPath(cfg: Record<string, unknown> | null | undefined, path: string): unknown {
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

function rowsOf(value: unknown, field: SchemaField, entry?: OutputConfigEntry | null): MapRow[] {
  const object = value !== null && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {}
  const rows: MapRow[] = []
  if (!isEntryMap(field)) {
    for (const [key, item] of Object.entries(object)) rows.push(newRow({ key, text: textOf(item, field), stored: true }))
    return rows
  }
  const keys = new Set([...Object.keys(object), ...storedSecretKeys(field, entry)])
  for (const key of keys) {
    const item = (object[key] ?? {}) as Record<string, unknown>
    for (const kind of ENTRY_KINDS) {
      if (kind === "secrets") {
        // The API removes secret values and flags them in secret_fields: one row stands for them.
        if (hasStoredSecrets(field, key, entry)) rows.push(newRow({ key, kind, stored: true }))
        continue
      }
      const list = item[kind]
      if (Array.isArray(list)) for (const text of list) rows.push(newRow({ key, kind, text: String(text), stored: true }))
    }
  }
  return rows
}

function escapePointer(part: string): string {
  return part.replaceAll("~", "~0").replaceAll("/", "~1")
}

/** secretPointer is the JSON pointer the API uses in secret_fields for a field path and optional entry key. */
function secretPointer(path: string, ...rest: string[]): string {
  return "/" + [...path.split("."), ...rest].map(escapePointer).join("/")
}

function hasStoredSecrets(field: SchemaField, key: string, entry?: OutputConfigEntry | null): boolean {
  return entry?.secret_fields?.[secretPointer(field.name, key, "secrets")] === true
}

/** The entry keys of field with stored secrets, including keys that hold nothing else. */
function storedSecretKeys(field: SchemaField, entry?: OutputConfigEntry | null): string[] {
  const prefix = secretPointer(field.name) + "/"
  const keys: string[] = []
  for (const [pointer, set] of Object.entries(entry?.secret_fields ?? {})) {
    if (!set || !pointer.startsWith(prefix) || !pointer.endsWith("/secrets")) continue
    const escaped = pointer.slice(prefix.length, -"/secrets".length)
    if (escaped.includes("/")) continue
    keys.push(escaped.replaceAll("~1", "/").replaceAll("~0", "~"))
  }
  return keys
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
      state[field.name] = { kind: "map", rows: rowsOf(getPath(cfg, field.name), field, entry) }
    } else {
      state[field.name] = { kind: "text", text: textOf(getPath(cfg, field.name), field) }
    }
  }
  return state
}

/** A duration is a string field whose bounds are duration strings. */
export function isDurationField(field: SchemaField): boolean {
  return field.type === "string" && (typeof field.min === "string" || typeof field.max === "string")
}

const DURATION_FORMAT = "must be a duration such as 30s or 1m"

/**
 * Why a typed number or duration is refused, worded as the server words it; null when it is
 * accepted. Integers must also be exact in JSON, so a value past 2^53 is out of range here.
 */
export function valueProblem(field: SchemaField, text: string): string | null {
  if (field.type === "int") {
    if (!/^-?\d+$/.test(text)) return "must be an integer"
    const n = Number(text)
    if (!Number.isSafeInteger(n)) return typeof field.min === "number" || typeof field.max === "number" ? rangeMessage("an integer", field) : "is out of range"
    if ((typeof field.min === "number" && n < field.min) || (typeof field.max === "number" && n > field.max)) return rangeMessage("an integer", field)
    return null
  }
  if (field.type === "float") {
    const n = Number(text)
    if (!/^-?(\d+\.?\d*|\.\d+)([eE][-+]?\d+)?$/.test(text) || !Number.isFinite(n)) return "must be a number"
    if ((typeof field.min === "number" && n < field.min) || (typeof field.max === "number" && n > field.max)) {
      return rangeMessage("a number", field)
    }
    return null
  }
  if (isDurationField(field)) {
    const ns = parseGoDuration(text)
    if (ns === null) return DURATION_FORMAT
    const lo = typeof field.min === "string" ? parseGoDuration(field.min) : null
    const hi = typeof field.max === "string" ? parseGoDuration(field.max) : null
    if ((lo !== null && ns < lo) || (hi !== null && ns > hi)) return `must be a duration between ${field.min} and ${field.max}`
  }
  return null
}

function rangeMessage(what: string, field: SchemaField): string {
  if (typeof field.min === "number" && typeof field.max === "number") return `must be ${what} between ${field.min} and ${field.max}`
  if (typeof field.min === "number") return `must be ${what} of at least ${field.min}`
  return `must be ${what} of at most ${field.max}`
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
      const problem = text === "" ? null : valueProblem(field, text)
      if (field.required && text === "") errors[field.name] = "Required"
      else if (problem) errors[field.name] = problem
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
  if (field.type === "int" || field.type === "float") return Number(trimmed)
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

function stringMapChanges(field: SchemaField, rows: MapRow[], previous: Record<string, unknown>, editing: boolean): Record<string, unknown> {
  const next = entryObject(rows, field)
  const changes: Record<string, unknown> = {}
  for (const [key, entry] of Object.entries(next)) if (!sameValue(entry, previous[key])) changes[key] = entry
  if (editing) for (const key of Object.keys(previous)) if (!(key in next)) changes[key] = null
  return changes
}

/**
 * Per entry key, only the kinds that changed. The server merges the patch: a kind left out keeps
 * its stored value, so an untouched stored secret is never named, and one the user removed is null.
 */
function entryMapChanges(
  field: SchemaField,
  rows: MapRow[],
  previous: Record<string, unknown>,
  stored: OutputConfigEntry | null | undefined,
): Record<string, unknown> {
  const kept = new Set(rows.filter((row) => row.kind === "secrets" && row.stored && !row.edited).map((row) => row.key.trim()))
  const next = entryObject(
    rows.filter((row) => !(row.kind === "secrets" && row.stored && !row.edited)),
    field,
  ) as Record<string, Record<string, string[]>>
  if (stored == null) return next

  const changes: Record<string, unknown> = {}
  const keys = new Set([...Object.keys(previous), ...storedSecretKeys(field, stored), ...Object.keys(next), ...kept])
  for (const key of keys) {
    const after = next[key] ?? {}
    const prior = (previous[key] ?? {}) as Record<string, unknown>
    const hadSecrets = hasStoredSecrets(field, key, stored)
    if (Object.keys(after).length === 0 && !kept.has(key)) {
      if (key in previous || hadSecrets) changes[key] = null
      continue
    }
    const change: Record<string, unknown> = {}
    for (const kind of ENTRY_KINDS) {
      if (kind === "secrets") {
        if (kept.has(key)) continue
        if (after.secrets) change.secrets = after.secrets
        else if (hadSecrets) change.secrets = null
        continue
      }
      if (!sameValue(after[kind], prior[kind])) change[kind] = after[kind] ?? null
    }
    if (Object.keys(change).length > 0) changes[key] = change
  }
  return changes
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
      const changes = isEntryMap(field)
        ? entryMapChanges(field, value.rows, (before ?? {}) as Record<string, unknown>, stored)
        : stringMapChanges(field, value.rows, (before ?? {}) as Record<string, unknown>, editing)
      if (Object.keys(changes).length > 0) setPath(patch, field.name, changes)
    }
  }
  return patch
}

/** The id of a field's control, for its label, its error and the focus after a refused save. */
export function fieldInputId(name: string): string {
  return `field-${name.replace(/[^\w-]/g, "-")}`
}

/** The schema field a configuration path names: "password_file", "tls.ca_file", `headers["X"].files[0]`. */
export function fieldOfPath(fields: readonly SchemaField[], path: string): string | null {
  let best: string | null = null
  for (const field of fields) {
    const names = [field.name]
    if (isSecretString(field)) names.push(`${field.name}_file`)
    for (const name of names) {
      const matches = path === name || path.startsWith(`${name}[`) || path.startsWith(`${name}.`)
      if (matches && (best === null || field.name.length > best.length)) best = field.name
    }
  }
  return best
}

/**
 * Finds the field a backend 400 message names. Messages put the location before the reason, after
 * any wrapping: "password_file: ...", "apply output: ...: slack: tls.ca_file: ...".
 */
export function fieldOfError(fields: readonly SchemaField[], message: string): { field: string; message: string } | null {
  const parts = message.split(": ")
  for (let i = 0; i < parts.length - 1; i++) {
    const field = fieldOfPath(fields, parts[i]!.trim())
    if (field) return { field, message: parts.slice(i + 1).join(": ").trim() || message }
  }
  return null
}

export interface RefusedSave {
  /** Field name to message, for the fields the form shows. */
  byField: Record<string, string>
  /** What no field of the form holds, as short lines. */
  other: string[]
}

/**
 * Splits a 400 into messages on the form's fields and the rest. The structured fields win; a body
 * without them falls back to the location at the front of the message.
 */
export function refusedSave(fields: readonly SchemaField[], driver: string, message: string, problems?: readonly FieldProblem[]): RefusedSave {
  const byField: Record<string, string> = {}
  const other: string[] = []
  if (problems && problems.length > 0) {
    for (const problem of problems) {
      const path = withoutDriver(problem.path.trim(), driver)
      const field = fieldOfPath(fields, path)
      if (field) byField[field] ??= problem.message
      else other.push(path ? `${path}: ${problem.message}` : problem.message)
    }
    return { byField, other }
  }
  const found = fieldOfError(fields, message)
  if (found) byField[found.field] = found.message
  else other.push(conciseError(message, driver))
  return { byField, other }
}

function withoutDriver(path: string, driver: string): string {
  return path.startsWith(`${driver}.`) ? path.slice(driver.length + 1) : path
}

// Wrapping the server adds on its way up: "apply output", "apply create", "catalog", `create "slack"`, "slack config".
const WRAPPER = /^(apply( \w+)?|catalog|(create|update|build|init|replace|restore)( "[^"]*")?|output( "[^"]*")?|[\w-]+ config)$/

/** The message without the server's wrapping prefixes, so the reason comes first. */
export function conciseError(message: string, driver: string): string {
  const parts = message.split(": ")
  let i = 0
  while (i < parts.length - 1 && (WRAPPER.test(parts[i]!.trim()) || parts[i]!.trim() === driver)) i++
  return parts.slice(i).join(": ")
}

/** The fields with errors in the order the form shows them; the first is the one to focus. */
export function erroredInOrder(order: readonly string[], errors: Record<string, string>): string[] {
  return order.filter((name) => errors[name])
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
