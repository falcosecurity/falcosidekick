import axios, {
  type AxiosAdapter,
  type AxiosError,
  type AxiosInstance,
  type AxiosResponse,
} from "axios"

import type {
  AuthLoginResponse,
  CountByResponse,
  Event,
  EventFilters,
  HistogramRequest,
  HistogramResult,
  MaskedConfig,
  OutputConfigEntry,
  OutputStatus,
  OutputType,
  PipelineComposite,
  PipelineLayout,
  SchemaField,
  SearchQuery,
  SearchResult,
  VersionInfo,
} from "./types"

/**
 * Single HTTP boundary for the UI. Every backend call in the app goes through
 * the helpers exported from this module. See the ESLint restricted-imports
 * rule that forbids direct `fetch` / `axios.*` usage elsewhere.
 */

const BASE_URL = "/api/v1"

let accessToken: string | null = null
let onUnauthorized: (() => void) | null = null

export function setAccessToken(token: string | null): void {
  accessToken = token
}

export function setUnauthorizedHandler(handler: (() => void) | null): void {
  onUnauthorized = handler
}

function createClient(): AxiosInstance {
  const client = axios.create({
    baseURL: BASE_URL,
    headers: { "Content-Type": "application/json" },
  })

  client.interceptors.request.use((config) => {
    if (accessToken) {
      config.headers.set("Authorization", `Bearer ${accessToken}`)
    }
    return config
  })

  client.interceptors.response.use(
    (response) => response,
    (error: AxiosError) => {
      if (error.response?.status === 401 && onUnauthorized) {
        onUnauthorized()
      }
      return Promise.reject(error)
    },
  )

  return client
}

const http = createClient()
const defaultAdapter = http.defaults.adapter

export function setApiAdapterForTests(adapter: AxiosAdapter | null): void {
  http.defaults.adapter = adapter ?? defaultAdapter
}

function paramsFromFilters(filters: EventFilters): URLSearchParams {
  const params = new URLSearchParams()
  if (filters.filter) params.set("filter", filters.filter)
  if (filters.priority?.length) params.set("priority", filters.priority.join(","))
  if (filters.rule?.length) params.set("rule", filters.rule.join(","))
  if (filters.source?.length) params.set("source", filters.source.join(","))
  if (filters.hostname?.length) params.set("hostname", filters.hostname.join(","))
  if (filters.tags?.length) params.set("tags", filters.tags.join(","))
  if (filters.since) params.set("since", filters.since)
  return params
}

function paramsFromQuery(query: SearchQuery): URLSearchParams {
  const params = paramsFromFilters(query)
  if (query.page != null) params.set("page", String(query.page))
  if (query.limit != null) params.set("limit", String(query.limit))
  if (query.sort_by) params.set("sort_by", query.sort_by)
  if (query.sort_desc != null) params.set("sort_desc", String(query.sort_desc))
  return params
}

function unwrap<T>(response: AxiosResponse<T>): T {
  return response.data
}

function normalizeOutputs(
  value: Record<string, OutputConfigEntry> | OutputConfigEntry[] | null | undefined,
): OutputConfigEntry[] {
  if (!value) return []
  if (Array.isArray(value)) return value
  return Object.values(value)
}

function normalizeStatusList(
  value: OutputStatus[] | { outputs: OutputStatus[] } | null | undefined,
): OutputStatus[] {
  if (!value) return []
  if (Array.isArray(value)) return value
  if (Array.isArray(value.outputs)) return value.outputs
  return []
}

function normalizeLayout(
  value: PipelineLayout | Record<string, never> | null | undefined,
): PipelineLayout {
  const fallback: PipelineLayout = {
    version: 0,
    updated_at: "",
    nodes: [],
    edges: [],
  }
  if (!value) return fallback
  const asLayout = value as Partial<PipelineLayout>
  return {
    version: asLayout.version ?? 0,
    updated_at: asLayout.updated_at ?? "",
    nodes: Array.isArray(asLayout.nodes) ? asLayout.nodes : [],
    edges: Array.isArray(asLayout.edges) ? asLayout.edges : [],
  }
}

type OutputTypeWire = {
  name: string
  category: string
  fields?: SchemaField[]
  schema?: {
    fields?: SchemaField[]
  }
}

function normalizeOutputTypes(
  value: OutputTypeWire[] | { types?: OutputTypeWire[] } | null | undefined,
): OutputType[] {
  const items = Array.isArray(value) ? value : Array.isArray(value?.types) ? value.types : []
  return items.map((item) => ({
    name: item.name,
    category: item.category,
    schema: {
      fields: Array.isArray(item.schema?.fields)
        ? item.schema.fields
        : Array.isArray(item.fields)
          ? item.fields
          : [],
    },
  }))
}

function normalizePipeline(data: {
  outputs: Record<string, OutputConfigEntry> | OutputConfigEntry[] | null
  status: OutputStatus[] | { outputs: OutputStatus[] } | null
  layout: PipelineLayout | Record<string, never> | null
}): PipelineComposite {
  return {
    outputs: normalizeOutputs(data.outputs),
    status: normalizeStatusList(data.status),
    layout: normalizeLayout(data.layout),
  }
}

export const api = {
  searchEvents(query: SearchQuery, signal?: AbortSignal): Promise<SearchResult> {
    return http
      .get<SearchResult>("/events/search", { params: paramsFromQuery(query), signal })
      .then(unwrap)
  },

  countEvents(filters: EventFilters, signal?: AbortSignal): Promise<number> {
    return http
      .get<{ count: number }>("/events/count", { params: paramsFromFilters(filters), signal })
      .then((r) => r.data.count)
  },

  countEventsBy(
    groupby: "priority" | "rule" | "source" | "tags" | "hostname",
    filters: EventFilters,
    signal?: AbortSignal,
  ): Promise<Record<string, number>> {
    return http
      .get<CountByResponse>(`/events/count/${groupby}`, {
        params: paramsFromFilters(filters),
        signal,
      })
      .then((r) => r.data.groups)
  },

  getEventsHistogram(req: HistogramRequest, signal?: AbortSignal): Promise<HistogramResult> {
    const params = paramsFromFilters(req)
    params.set("bucket_ms", String(req.bucket_ms))
    if (req.group_by) params.set("group_by", req.group_by)
    return http
      .get<HistogramResult>("/events/histogram", { params, signal })
      .then(unwrap)
  },

  getEvent(uuid: string, signal?: AbortSignal): Promise<Event | null> {
    return http
      .get<Event>(`/events/${encodeURIComponent(uuid)}`, { signal })
      .then(unwrap)
      .catch((err: AxiosError) => {
        if (err.response?.status === 404) return null
        throw err
      })
  },

  getPipeline(signal?: AbortSignal): Promise<PipelineComposite> {
    return http
      .get<{
        outputs: Record<string, OutputConfigEntry> | OutputConfigEntry[] | null
        status: OutputStatus[] | { outputs: OutputStatus[] } | null
        layout: PipelineLayout | Record<string, never> | null
      }>("/pipeline", { signal })
      .then((r) => normalizePipeline(r.data))
  },

  getPipelineStatus(signal?: AbortSignal): Promise<OutputStatus[]> {
    return http
      .get<OutputStatus[] | { outputs: OutputStatus[] } | null>("/pipeline/status", { signal })
      .then((r) => normalizeStatusList(r.data))
  },

  getPipelineLayout(signal?: AbortSignal): Promise<PipelineLayout> {
    return http
      .get<PipelineLayout | Record<string, never>>("/pipeline/layout", { signal })
      .then((r) => normalizeLayout(r.data))
  },

  getOutputs(signal?: AbortSignal): Promise<OutputConfigEntry[]> {
    return http
      .get<Record<string, OutputConfigEntry> | OutputConfigEntry[] | null>("/pipeline/outputs", {
        signal,
      })
      .then((r) => normalizeOutputs(r.data))
  },

  getOutput(name: string, signal?: AbortSignal): Promise<OutputConfigEntry | null> {
    return http
      .get<OutputConfigEntry>(`/pipeline/outputs/${encodeURIComponent(name)}`, { signal })
      .then(unwrap)
      .catch((err: AxiosError) => {
        if (err.response?.status === 404) return null
        throw err
      })
  },

  getOutputTypes(signal?: AbortSignal): Promise<OutputType[]> {
    return http
      .get<OutputTypeWire[] | { types?: OutputTypeWire[] } | null>("/pipeline/outputs/types", {
        signal,
      })
      .then((r) => normalizeOutputTypes(r.data))
  },

  getConfig(signal?: AbortSignal): Promise<MaskedConfig> {
    return http.get<MaskedConfig>("/config", { signal }).then(unwrap)
  },

  getVersion(signal?: AbortSignal): Promise<VersionInfo> {
    return http.get<VersionInfo>("/version", { signal }).then(unwrap)
  },

  login(username: string, password: string, signal?: AbortSignal): Promise<AuthLoginResponse> {
    return http
      .post<AuthLoginResponse>("/auth/login", { username, password }, { signal })
      .then(unwrap)
  },
}

export type Api = typeof api
