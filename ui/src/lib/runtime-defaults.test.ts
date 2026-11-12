import { describe, expect, test } from "bun:test"

import { normalizeConfig } from "@/lib/api-client"
import type { RuntimeConfig, SchemaField } from "@/lib/types"
import { fixtures } from "@/test/fixtures"

import { withRuntimeDefaults } from "./runtime-defaults"

const FIELDS = [
  { name: "host", type: "string", label: "Host", required: true, default: "" },
  { name: "runtime.workers", type: "int", label: "Workers", required: false, default: 2 },
  { name: "runtime.retry.initial_interval", type: "string", label: "Initial interval", required: false, default: "1s" },
  { name: "runtime.batching.enabled", type: "bool", label: "Batching", required: false, default: false },
  { name: "runtime.minimum_priority", type: "enum", label: "Minimum priority", required: false },
] as SchemaField[]

describe("withRuntimeDefaults", () => {
  test("runtime fields default to what the running configuration sets, in the schema's units", () => {
    // As api.getConfig hands it over: the API writes Falco's "Warning", the UI reads "warning".
    const defaults = normalizeConfig(fixtures.config).config.runtime_defaults as RuntimeConfig
    const byName = Object.fromEntries(withRuntimeDefaults(FIELDS, defaults).map((f) => [f.name, f.default]))
    expect(byName).toEqual({
      host: "",
      "runtime.workers": 1,
      "runtime.retry.initial_interval": "10ms",
      "runtime.batching.enabled": true,
      "runtime.minimum_priority": "warning",
    })
  })

  test("durations arrive as Go duration strings and are kept as written", () => {
    const defaults = { minimum_priority: "", queue_size: 1, workers: 1, retry: { initial_interval: "1.5s", max_interval: "1m", max_attempts: 3, multiplier: 2 } } as RuntimeConfig
    const byName = Object.fromEntries(withRuntimeDefaults(FIELDS, defaults).map((f) => [f.name, f.default]))
    expect(byName["runtime.retry.initial_interval"]).toBe("1.5s")
  })

  test("a default the output owns is kept, whatever runtime_defaults says", () => {
    // policyreport batches by default; runtime_defaults turns batching off for every other output.
    const own = FIELDS.map((f) => (f.name === "runtime.batching.enabled" ? { ...f, default: true, output_default: true } : f))
    const defaults = { minimum_priority: "", queue_size: 1, workers: 4, batching: { enabled: false, batch_size: 100, flush_interval: "1s" } } as RuntimeConfig
    const byName = Object.fromEntries(withRuntimeDefaults(own, defaults).map((f) => [f.name, f.default]))
    expect(byName["runtime.batching.enabled"]).toBe(true)
    expect(byName["runtime.workers"]).toBe(4)
  })

  test("the policyreport schema from the API keeps batching on by default", () => {
    const policyreport = fixtures.outputTypes.types?.find((t) => t.name === "policyreport")
    expect(policyreport).toBeDefined()
    const defaults = { minimum_priority: "", queue_size: 1, workers: 1, batching: { enabled: false, batch_size: 500, flush_interval: "1s" } } as RuntimeConfig
    const enabled = withRuntimeDefaults(policyreport?.schema.fields ?? [], defaults).find((f) => f.name === "runtime.batching.enabled")
    expect(enabled?.default).toBe(true)
  })

  test("without the running configuration, or for a value it leaves empty, the catalog default stays", () => {
    expect(withRuntimeDefaults(FIELDS, undefined)).toEqual(FIELDS)
    const empty = { minimum_priority: "", queue_size: 0, workers: 4 } as RuntimeConfig
    const byName = Object.fromEntries(withRuntimeDefaults(FIELDS, empty).map((f) => [f.name, f.default]))
    expect(byName["runtime.minimum_priority"]).toBeUndefined()
    expect(byName["runtime.workers"]).toBe(4)
    expect(byName["runtime.retry.initial_interval"]).toBe("1s")
  })
})
