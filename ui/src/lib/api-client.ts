import axios, {
  type AxiosAdapter,
  type AxiosError,
  type AxiosInstance,
  type AxiosResponse,
} from "axios"

import { ApiError } from "./api-error"
import type {
  AuthLoginResponse,
  CountByResponse,
  Event,
  EventFilters,
  GroupBy,
  HistogramRequest,
  HistogramResult,
  LayoutNode,
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

function toApiError(error: AxiosError): ApiError {
  const status = error.response?.status ?? 0
  const body: unknown = error.response?.data
  const text =
    body && typeof body === "object" && typeof (body as { error?: unknown }).error === "string"
      ? (body as { error: string }).error
      : null
  if (text) return new ApiError(status, text)
  if (status > 0) return new ApiError(status, `Request failed with status ${status}`)
  return new ApiError(0, "Unable to reach the server")
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
    (error: unknown) => {
      if (axios.isCancel(error) || !axios.isAxiosError(error)) {
        return Promise.reject(error)
      }
      if (error.response?.status === 401 && onUnauthorized) {
        onUnauthorized()
      }
      return Promise.reject(toApiError(error))
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

function nullOn404<T>(err: unknown): T | null {
  if (err instanceof ApiError && err.status === 404) return null
  throw err
}

// Wire shapes: the server keys outputs by name, wraps status lists and sends an empty object
// for a layout that was never saved.
export type OutputsWire = Record<string, OutputConfigEntry> | null
export type StatusListWire = { outputs: OutputStatus[] }
export type LayoutWire = { updated_at: string; nodes: LayoutNode[] | null } | Record<string, never> | null
export type OutputTypeWire = { name: string; category: string; schema: { fields: SchemaField[] | null } }
export type OutputTypesWire = { types: OutputTypeWire[] | null }
export type PipelineWire = { outputs: OutputsWire; status: OutputStatus[] | null; layout: LayoutWire }

export function normalizeOutputs(value: OutputsWire): OutputConfigEntry[] {
  return value ? Object.values(value) : []
}

export function normalizeStatusList(value: OutputStatus[] | null | undefined): OutputStatus[] {
  return value ?? []
}

export function normalizeLayout(value: LayoutWire): PipelineLayout {
  if (!value || !("nodes" in value)) return { updated_at: "", nodes: [] }
  return { updated_at: value.updated_at ?? "", nodes: value.nodes ?? [] }
}

export function normalizeOutputTypes(value: OutputTypesWire): OutputType[] {
  return (value.types ?? []).map((item) => ({
    name: item.name,
    category: item.category,
    schema: { fields: item.schema.fields ?? [] },
  }))
}

export function normalizePipeline(data: PipelineWire): PipelineComposite {
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

  countEventsBy(groupby: GroupBy, filters: EventFilters, signal?: AbortSignal): Promise<Record<string, number>> {
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
      .catch(nullOn404<Event>)
  },

  getPipeline(signal?: AbortSignal): Promise<PipelineComposite> {
    return http.get<PipelineWire>("/pipeline", { signal }).then((r) => normalizePipeline(r.data))
  },

  getPipelineStatus(signal?: AbortSignal): Promise<OutputStatus[]> {
    return http
      .get<StatusListWire>("/pipeline/status", { signal })
      .then((r) => normalizeStatusList(r.data.outputs))
  },

  getPipelineLayout(signal?: AbortSignal): Promise<PipelineLayout> {
    return http.get<LayoutWire>("/pipeline/layout", { signal }).then((r) => normalizeLayout(r.data))
  },

  getOutputs(signal?: AbortSignal): Promise<OutputConfigEntry[]> {
    return http.get<OutputsWire>("/pipeline/outputs", { signal }).then((r) => normalizeOutputs(r.data))
  },

  getOutput(name: string, signal?: AbortSignal): Promise<OutputConfigEntry | null> {
    return http
      .get<OutputConfigEntry>(`/pipeline/outputs/${encodeURIComponent(name)}`, { signal })
      .then(unwrap)
      .catch(nullOn404<OutputConfigEntry>)
  },

  getOutputTypes(signal?: AbortSignal): Promise<OutputType[]> {
    return http
      .get<OutputTypesWire>("/pipeline/outputs/types", { signal })
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
