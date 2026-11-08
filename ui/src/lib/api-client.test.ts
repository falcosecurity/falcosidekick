import { afterEach, describe, expect, test } from "bun:test"
import { AxiosError, CanceledError, type InternalAxiosRequestConfig } from "axios"

import { composite, errorResponse, fixtureAdapter, fixtures, networkError, outputs, statuses } from "@/test/fixtures"

import { ApiError } from "./api-error"
import { api, normalizeLayout, setAccessToken, setApiAdapterForTests, setUnauthorizedHandler } from "./api-client"
import { CIRCUIT_STATES, OUTPUT_STATUS_STATES, PRIORITIES } from "./types"

function paramsOf(config: InternalAxiosRequestConfig): URLSearchParams {
  return config.params as URLSearchParams
}

function useFailingAdapter(status: number, body?: unknown): void {
  setApiAdapterForTests(async (config) => {
    throw errorResponse(config, status, body)
  })
}

afterEach(() => {
  setAccessToken(null)
  setUnauthorizedHandler(null)
  setApiAdapterForTests(null)
})

describe("api-client requests", () => {
  test("attaches the bearer token and serializes search params", async () => {
    const calls: InternalAxiosRequestConfig[] = []
    setApiAdapterForTests(fixtureAdapter(calls))
    setAccessToken("abc123")

    const result = await api.searchEvents({
      filter: "shell",
      priority: ["critical", "error"],
      source: ["syscall"],
      page: 2,
      limit: 50,
      sort_by: "timestamp",
      sort_desc: false,
    })

    expect(result.events.map((e) => e.uuid)).toEqual(fixtures.eventsSearch.events.map((e) => e.uuid))
    expect(calls[0]?.url).toBe("/events/search")
    expect(calls[0]?.headers.get("Authorization")).toBe("Bearer abc123")
    const params = paramsOf(calls[0]!)
    expect(params.get("filter")).toBe("shell")
    expect(params.get("priority")).toBe("critical,error")
    expect(params.get("source")).toBe("syscall")
    expect(params.get("page")).toBe("2")
    expect(params.get("limit")).toBe("50")
    expect(params.get("sort_desc")).toBe("false")
  })

  test("maps every helper to its backend route", async () => {
    const calls: InternalAxiosRequestConfig[] = []
    setApiAdapterForTests(fixtureAdapter(calls))

    await expect(api.countEvents({ since: "1h", tags: ["shell", "network"] })).resolves.toBe(fixtures.eventsCount.count)
    expect(calls.at(-1)?.url).toBe("/events/count")
    expect(paramsOf(calls.at(-1)!).get("tags")).toBe("shell,network")

    await expect(api.countEventsBy("priority", { priority: ["critical"] })).resolves.toEqual(
      fixtures.eventsCountByPriority.groups,
    )
    expect(calls.at(-1)?.url).toBe("/events/count/priority")

    const histogram = await api.getEventsHistogram({ since: "6h", bucket_ms: 3_600_000, group_by: "source" })
    expect(histogram.buckets).toHaveLength(6)
    expect(paramsOf(calls.at(-1)!).get("bucket_ms")).toBe("3600000")
    expect(paramsOf(calls.at(-1)!).get("group_by")).toBe("source")

    await expect(api.getEvent(fixtures.event.uuid)).resolves.toEqual(fixtures.event)
    await expect(api.getPipelineLayout()).resolves.toEqual(normalizeLayout(fixtures.layout))
    await expect(api.getOutput("webhook")).resolves.toEqual(fixtures.output)
    expect(calls.at(-1)?.url).toBe("/pipeline/outputs/webhook")
    await expect(api.getConfig()).resolves.toEqual(fixtures.config)
    await expect(api.getVersion()).resolves.toEqual(fixtures.version)
    expect(calls.at(-1)?.url).toBe("/version")
  })

  test("encodes path parameters", async () => {
    const calls: InternalAxiosRequestConfig[] = []
    setApiAdapterForTests(fixtureAdapter(calls))
    await api.getEvent("event/id").catch(() => null)
    expect(calls.at(-1)?.url).toBe("/events/event%2Fid")
    await api.getOutput("slack/main").catch(() => null)
    expect(calls.at(-1)?.url).toBe("/pipeline/outputs/slack%2Fmain")
  })

  test("returns null for not-found nullable lookups", async () => {
    setApiAdapterForTests(fixtureAdapter())
    await expect(api.getEvent("missing")).resolves.toBeNull()
    await expect(api.getOutput("missing")).resolves.toBeNull()
  })
})

describe("api-client normalization of the real responses", () => {
  test("flattens the pipeline composite into arrays and a layout", async () => {
    setApiAdapterForTests(fixtureAdapter())
    const pipeline = await api.getPipeline()
    expect(pipeline).toEqual(composite)
    expect(pipeline.outputs.map((o) => o.name)).toEqual(["alertmanager", "inmemory", "webhook"])
    expect(pipeline.outputs.every((o) => !("type" in o))).toBe(true)
    expect(pipeline.layout.nodes.map((n) => n.id)).toContain("sink:webhook")
    expect(pipeline.layout.updated_at).not.toBe("")
  })

  test("unwraps the status list and the outputs map", async () => {
    setApiAdapterForTests(fixtureAdapter())
    await expect(api.getPipelineStatus()).resolves.toEqual(statuses)
    await expect(api.getOutputs()).resolves.toEqual(outputs)
  })

  test("statuses only use the states and circuits the backend emits", () => {
    for (const status of statuses) {
      expect(OUTPUT_STATUS_STATES).toContain(status.status)
      expect(status.circuit_state === "" || CIRCUIT_STATES.includes(status.circuit_state)).toBe(true)
      expect(typeof status.last_success).toBe("string")
      expect(typeof status.events_per_minute).toBe("number")
      expect("send_latency_p99_ms" in status).toBe(false)
    }
    expect(statuses.find((s) => s.name === "alertmanager")?.status).toBe("failed")
    expect(statuses.find((s) => s.name === "alertmanager")?.circuit_state).toBe("")
  })

  test("events carry the fields the table renders", () => {
    for (const event of fixtures.eventsSearch.events) {
      expect(PRIORITIES).toContain(event.priority)
      expect(typeof event.uuid).toBe("string")
      expect(typeof event.time).toBe("string")
      expect(typeof event.rule).toBe("string")
      expect(typeof event.output_fields).toBe("object")
    }
  })

  test("output types expose the catalog with the declared field order", async () => {
    setApiAdapterForTests(fixtureAdapter())
    const types = await api.getOutputTypes()
    expect(types.map((t) => t.name)).toEqual([
      "alertmanager", "awss3", "awssns", "awssqs", "cloudevents", "datadog", "discord", "elasticsearch",
      "gcppubsub", "grafanaoncall", "inmemory", "kafka", "loki", "opsgenie", "otlp", "pagerduty",
      "policyreport", "redis", "slack", "smtp", "syslog", "talon", "teams", "webhook",
    ])
    const webhook = types.find((t) => t.name === "webhook")!
    expect(webhook.schema.fields[0]?.name).toBe("host")
    const fieldTypes = new Set(types.flatMap((t) => t.schema.fields.flatMap((f) => [f.type, ...(f.entry_fields ?? []).map((e) => e.type)])))
    expect([...fieldTypes].sort()).toEqual(["bool", "enum", "float", "int", "map", "string", "string[]"])
  })

  test("tolerates the null and empty shapes the server sends", async () => {
    setApiAdapterForTests(async (config) => ({
      data: config.url === "/pipeline/layout" ? {} : { outputs: null, status: [], layout: null },
      status: 200, statusText: "OK", headers: {}, config,
    }))
    await expect(api.getPipelineLayout()).resolves.toEqual({ updated_at: "", nodes: [] })
    await expect(api.getPipeline()).resolves.toEqual({ outputs: [], status: [], layout: { updated_at: "", nodes: [] } })

    setApiAdapterForTests(async (config) => ({
      data: { types: [{ name: "noop", category: "test", schema: { fields: null } }] },
      status: 200, statusText: "OK", headers: {}, config,
    }))
    await expect(api.getOutputTypes()).resolves.toEqual([{ name: "noop", category: "test", schema: { fields: [] } }])
  })

  test("keeps configured-secret metadata and config objects untouched", async () => {
    setApiAdapterForTests(fixtureAdapter())
    const [webhook] = (await api.getOutputs()).filter((o) => o.name === "webhook")
    expect(webhook?.secret_fields).toEqual({ "/headers/X-Api-Key/secrets": true })
    expect(webhook?.config).toEqual(fixtures.output.config)
    expect(Object.hasOwn((webhook?.config as { headers: Record<string, object> }).headers["X-Api-Key"]!, "secrets")).toBe(false)
  })
})

describe("api-client errors", () => {
  test.each(Object.entries(fixtures.errors))("surfaces the backend text of %s as an ApiError", async (_name, { status, body }) => {
    useFailingAdapter(status, body)
    const error = await api.getVersion().catch((e: unknown) => e)
    expect(error).toBeInstanceOf(ApiError)
    expect((error as ApiError).status).toBe(status)
    expect((error as ApiError).message).toBe(body.error)
  })

  test("describes answers without an error envelope by their status", async () => {
    useFailingAdapter(502, "<html>bad gateway</html>")
    const error = await api.getVersion().catch((e: unknown) => e)
    expect(error).toBeInstanceOf(ApiError)
    expect((error as ApiError).status).toBe(502)
    expect((error as ApiError).message).toBe("Request failed with status 502")
  })

  test("describes an unreachable server without a status", async () => {
    setApiAdapterForTests(async (config) => {
      throw networkError(config)
    })
    const error = await api.getVersion().catch((e: unknown) => e)
    expect(error).toBeInstanceOf(ApiError)
    expect((error as ApiError).status).toBe(0)
    expect((error as ApiError).message).toBe("Unable to reach the server")
  })

  test("passes cancellations through untouched", async () => {
    setApiAdapterForTests(async (config) => {
      throw new CanceledError("canceled", AxiosError.ERR_CANCELED, config)
    })
    const error = await api.getVersion().catch((e: unknown) => e)
    expect(error).not.toBeInstanceOf(ApiError)
    expect(error).toBeInstanceOf(CanceledError)
  })

  test("invokes the unauthorized handler on 401 responses", async () => {
    let called = 0
    setUnauthorizedHandler(() => {
      called += 1
    })
    useFailingAdapter(401, { error: "unauthorized" })
    await expect(api.getVersion()).rejects.toBeInstanceOf(ApiError)
    expect(called).toBe(1)
  })
})
