import { formatGoDuration } from "@/lib/format"
import type { RuntimeConfig, SchemaField } from "@/lib/types"

const RUNTIME_PREFIX = "runtime."

/**
 * The schema with the defaults an output really inherits: Sidekick merges each output's runtime
 * over runtime_defaults from its configuration, so the catalog default of a runtime field is only
 * the default of that default.
 */
export function withRuntimeDefaults(fields: readonly SchemaField[], defaults: RuntimeConfig | undefined): SchemaField[] {
  if (!defaults) return [...fields]
  return fields.map((field) => {
    if (!field.name.startsWith(RUNTIME_PREFIX)) return field
    const inherited = inheritedValue(defaults, field.name.slice(RUNTIME_PREFIX.length))
    if (inherited === undefined) return field
    // Durations travel as nanoseconds; the schema writes them as Go duration text.
    const value = typeof inherited === "number" && typeof field.default === "string" ? formatGoDuration(inherited) : inherited
    return { ...field, default: value }
  })
}

function inheritedValue(defaults: RuntimeConfig, path: string): string | number | boolean | undefined {
  let current: unknown = defaults
  for (const part of path.split(".")) {
    if (current === null || typeof current !== "object") return undefined
    current = (current as Record<string, unknown>)[part]
  }
  // An empty minimum priority means "every priority": the schema default already says so.
  if (current === "" || current === null) return undefined
  return typeof current === "string" || typeof current === "number" || typeof current === "boolean" ? current : undefined
}
