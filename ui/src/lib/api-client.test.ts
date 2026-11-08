import { afterEach, describe, expect, test } from "bun:test"
import type {
  AxiosAdapter,
  AxiosResponse,
  InternalAxiosRequestConfig,
} from "axios"

import {
  api,
  setAccessToken,
  setApiAdapterForTests,
  setUnauthorizedHandler,
} from "./api-client"
import type { Event, OutputConfigEntry, OutputStatus, SchemaField } from "./types"

function response<T>(config: InternalAxiosRequestConfig, data: T): AxiosResponse<T> {
  return {
    data,
    status: 200,
    statusText: "OK",
    headers: {},
    config,
  }
}

function useJsonAdapter<T>(
  data: T,
  calls: InternalAxiosRequestConfig[] = [],
): InternalAxiosRequestConfig[] {
  const adapter: AxiosAdapter = async (config) => {
    calls.push(config)
    return response(config, data)
  }
  setApiAdapterForTests(adapter)
  return calls
}

function useRejectingAdapter(status: number): void {
  setApiAdapterForTests(async () => Promise.reject({ response: { status } }))
}

function paramsOf(config: InternalAxiosRequestConfig): URLSearchParams {
  return config.params as URLSearchParams
}

const event: Event = {
  uuid: "evt-1",
  output: "shell spawned",
  priority: "critical",
  rule: "Terminal shell in container",
  time: "2026-04-27T12:00:00Z",
  output_fields: {},
  source: "syscall",
  tags: ["shell"],
  hostname: "node-1",
}

const outputEntry: OutputConfigEntry = {
  name: "slack",
  type: "slack",
  config: {},
  provisioned: true,
  version: 1,
  updated_at: "2026-04-27T12:00:00Z",
}

const status: OutputStatus = {
  name: "slack",
  status: "ok",
  queue_depth: 0,
  queue_capacity: 100,
  sent_total: 3,
  dropped_total: 0,
  failed_total: 0,
  events_per_minute: 2,
  circuit_state: "closed",
  last_success: "2026-04-27T12:00:00Z",
  last_error: "",
}

describe("api-client state helpers", () => {
  afterEach(() => {
    setAccessToken(null)
    setUnauthorizedHandler(null)
    setApiAdapterForTests(null)
  })

  test("setAccessToken accepts string and null without throwing", () => {
    setAccessToken("abc123")
    setAccessToken(null)
    expect(true).toBe(true)
  })

  test("setUnauthorizedHandler accepts handler and null without throwing", () => {
    const handler = () => undefined
    setUnauthorizedHandler(handler)
    setUnauthorizedHandler(null)
    expect(true).toBe(true)
  })

  test("attaches bearer token and serializes search params", async () => {
    const calls = useJsonAdapter({ events: [event], total: 1, page: 2, limit: 50 })
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

    expect(result.events[0]?.uuid).toBe("evt-1")
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

  test("invokes unauthorized handler on 401 responses", async () => {
    let called = 0
    setUnauthorizedHandler(() => {
      called += 1
    })
    useRejectingAdapter(401)

    await expect(api.getVersion()).rejects.toBeDefined()
    expect(called).toBe(1)
  })

  test("returns null for not-found nullable lookups", async () => {
    useRejectingAdapter(404)
    await expect(api.getEvent("missing")).resolves.toBeNull()

    useRejectingAdapter(404)
    await expect(api.getOutput("missing")).resolves.toBeNull()
  })

  test("normalizes pipeline envelopes from backend responses", async () => {
    useJsonAdapter({
      outputs: { slack: outputEntry },
      status: { outputs: [status] },
      layout: {},
    })

    const result = await api.getPipeline()

    expect(result.outputs).toEqual([outputEntry])
    expect(result.status).toEqual([status])
    expect(result.layout).toEqual({ version: 0, updated_at: "", nodes: [], edges: [] })
  })

  test("normalizes list endpoints and output type schemas", async () => {
    useJsonAdapter({ outputs: [status] })
    await expect(api.getPipelineStatus()).resolves.toEqual([status])

    useJsonAdapter({ slack: outputEntry })
    await expect(api.getOutputs()).resolves.toEqual([outputEntry])

    useJsonAdapter({
      types: [
        {
          name: "slack",
          category: "chat",
          schema: {
            fields: [{ name: "secret_endpoint", type: "secret", label: "Secret Endpoint", required: true }],
          },
        },
        {
          name: "legacy",
          category: "test",
          fields: [{ name: "host", type: "string", label: "Host", required: true }],
        },
      ],
    })

    await expect(api.getOutputTypes()).resolves.toEqual([
      {
        name: "slack",
        category: "chat",
        schema: {
          fields: [{ name: "secret_endpoint", type: "secret", label: "Secret Endpoint", required: true }],
        },
      },
      {
        name: "legacy",
        category: "test",
        schema: { fields: [{ name: "host", type: "string", label: "Host", required: true }] },
      },
    ])
  })

  test.each(["map", "array"])("preserves configured-secret metadata through %s output normalization", async (shape) => {
    const config = Object.freeze({
      headers: Object.freeze({ "X/Api~Key": Object.freeze({ values: Object.freeze(["public", "****"]) }) }),
    })
    const secretFields = Object.freeze({
      "/password": true, "/headers/X~1Api~0Key/secrets": false, "/__proto__/token": true,
    })
    const entry: OutputConfigEntry = Object.freeze({ ...outputEntry, config, secret_fields: secretFields })
    const outputs = shape === "map" ? Object.freeze({ slack: entry }) : Object.freeze([entry])
    const before = JSON.stringify(outputs)
    useJsonAdapter({ outputs, status: [], layout: null })
    const pipeline = await api.getPipeline()
    expect(pipeline.outputs).toEqual([entry])
    expect(pipeline.outputs[0]?.secret_fields).toBe(secretFields)
    expect(pipeline.outputs[0]?.config).toBe(config)

    useJsonAdapter(outputs)
    const list = await api.getOutputs()
    expect(list).toEqual([entry])
    expect(list[0]?.secret_fields).toBe(secretFields)
    expect(list[0]?.config).toBe(config)
    expect(JSON.stringify(outputs)).toBe(before)
    expect(Object.hasOwn(config.headers["X/Api~Key"], "secrets")).toBe(false)
  })

  test("preserves secret-only config and metadata in a detail response", async () => {
    const entry: OutputConfigEntry = Object.freeze({
      ...outputEntry, type: "unknown", config: Object.freeze({}),
      secret_fields: Object.freeze({ "/password": true, "/headers/X-Api-Key/secrets": false }),
    })
    useJsonAdapter(entry)
    const result = await api.getOutput("slack")
    expect(result).toBe(entry)
    expect(result?.config).toEqual({})
    expect(result?.secret_fields).toEqual({ "/password": true, "/headers/X-Api-Key/secrets": false })
  })

  test.each(["schema", "flat"])("preserves map entry_fields and string-list types in %s schemas", async (shape) => {
    const fields: SchemaField[] = [{
      name: "headers", type: "map", label: "Headers", required: false,
      entry_fields: [
        { name: "values", type: "string[]", label: "Values", required: false },
        { name: "secrets", type: "string[]", label: "Secrets", required: false, secret: true },
        { name: "files", type: "string[]", label: "Files", required: false },
      ],
    }]
    const outputType = { name: "webhook", category: "http" }
    useJsonAdapter({ types: [shape === "schema" ? { ...outputType, schema: { fields } } : { ...outputType, fields }] })
    const result = await api.getOutputTypes()
    expect(result).toEqual([{ ...outputType, schema: { fields } }])
    expect(result[0]?.schema.fields).toBe(fields)
  })

  test("maps remaining API helpers to their backend routes", async () => {
    const calls: InternalAxiosRequestConfig[] = []

    useJsonAdapter({ count: 12 }, calls)
    await api.countEvents({ since: "1h", tags: ["shell", "network"] })
    expect(calls.at(-1)?.url).toBe("/events/count")
    expect(paramsOf(calls.at(-1)!).get("tags")).toBe("shell,network")

    useJsonAdapter({ groups: { syscall: 4 } }, calls)
    await api.countEventsBy("source", { priority: ["critical"] })
    expect(calls.at(-1)?.url).toBe("/events/count/source")

    useJsonAdapter({ buckets: [], bucket_ms: 60_000, from: 0, to: 60_000 }, calls)
    await api.getEventsHistogram({ since: "1h", bucket_ms: 60_000, group_by: "source" })
    expect(calls.at(-1)?.url).toBe("/events/histogram")
    expect(paramsOf(calls.at(-1)!).get("bucket_ms")).toBe("60000")
    expect(paramsOf(calls.at(-1)!).get("group_by")).toBe("source")

    useJsonAdapter(event, calls)
    await api.getEvent("event/id")
    expect(calls.at(-1)?.url).toBe("/events/event%2Fid")

    useJsonAdapter({ version: 2, updated_at: "now", nodes: [], edges: [] }, calls)
    await api.getPipelineLayout()
    expect(calls.at(-1)?.url).toBe("/pipeline/layout")

    useJsonAdapter(outputEntry, calls)
    await api.getOutput("slack/main")
    expect(calls.at(-1)?.url).toBe("/pipeline/outputs/slack%2Fmain")

    useJsonAdapter({ config: {}, version: 1, updated_at: "now" }, calls)
    await api.getConfig()
    expect(calls.at(-1)?.url).toBe("/config")

    useJsonAdapter({ version: "v3" }, calls)
    await api.getVersion()
    expect(calls.at(-1)?.url).toBe("/version")

    useJsonAdapter(
      {
        access_token: "token",
        refresh_token: "refresh",
        expires_at: "later",
        refresh_expires_at: "later",
      },
      calls,
    )
    await api.login("admin", "secret")
    expect(calls.at(-1)?.url).toBe("/auth/login")
    expect(calls.at(-1)?.method).toBe("post")
  })
})
