import { describe, expect, test } from "bun:test"

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
    const defaults = fixtures.config.config.runtime_defaults as RuntimeConfig
    const byName = Object.fromEntries(withRuntimeDefaults(FIELDS, defaults).map((f) => [f.name, f.default]))
    expect(byName).toEqual({
      host: "",
      "runtime.workers": 1,
      "runtime.retry.initial_interval": "10ms",
      "runtime.batching.enabled": true,
      "runtime.minimum_priority": "warning",
    })
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
