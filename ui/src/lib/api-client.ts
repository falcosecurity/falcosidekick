import axios, {
  type AxiosAdapter,
  type AxiosError,
  type AxiosInstance,
  type AxiosResponse,
} from "axios"

import { ApiError, errorDetails } from "./api-error"
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
  SavedOutput,
  SchemaField,
  SearchQuery,
  SearchResult,
  SecretsListing,
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
  if (text) return new ApiError(status, text, errorDetails(body))
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

// List filters repeat their parameter once per value: rule names, hostnames and tags may hold commas.
const LIST_FILTERS = ["priority", "rule", "source", "hostname", "tags"] as const

function paramsFromFilters(filters: EventFilters): URLSearchParams {
  const params = new URLSearchParams()
  if (filters.filter) params.set("filter", filters.filter)
  for (const key of LIST_FILTERS) for (const value of filters[key] ?? []) params.append(key, value)
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
export type OutputTypeWire = {
  name: string
  category: string
  event_source?: boolean
  schema: { fields: SchemaField[] | null }
}
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
    event_source: item.event_source,
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

/**
 * The API writes priorities as Falco does ("Warning"); the UI keys its colours, labels and filters by
 * the lowercase name, so every priority is lowercased here, once, as it arrives.
 */
export function normalizeEvent(evt: Event): Event {
  return { ...evt, priority: String(evt.priority).toLowerCase() as Event["priority"] }
}

function lowercaseKeys(groups: Record<string, number> | undefined): Record<string, number> {
  const out: Record<string, number> = {}
  for (const [key, value] of Object.entries(groups ?? {})) out[key.toLowerCase()] = (out[key.toLowerCase()] ?? 0) + value
  return out
}

export function normalizeHistogram(result: HistogramResult): HistogramResult {
  if (result.group_by !== "priority") return result
  return { ...result, buckets: result.buckets.map((b) => (b.by ? { ...b, by: lowercaseKeys(b.by) } : b)) }
}

export function normalizeConfig(masked: MaskedConfig): MaskedConfig {
  const defaults = masked.config?.runtime_defaults
  if (!defaults?.minimum_priority) return masked
  return {
    ...masked,
    config: { ...masked.config, runtime_defaults: { ...defaults, minimum_priority: defaults.minimum_priority.toLowerCase() } },
  }
}

export const api = {
  searchEvents(query: SearchQuery, signal?: AbortSignal): Promise<SearchResult> {
    return http
      .get<SearchResult>("/events/search", { params: paramsFromQuery(query), signal })
      .then(unwrap)
      .then((r) => ({ ...r, events: (r.events ?? []).map(normalizeEvent) }))
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
      .then((r) => (groupby === "priority" ? lowercaseKeys(r.data.groups) : r.data.groups))
  },

  getEventsHistogram(req: HistogramRequest, signal?: AbortSignal): Promise<HistogramResult> {
    const params = paramsFromFilters(req)
    params.set("bucket_ms", String(req.bucket_ms))
    if (req.group_by) params.set("group_by", req.group_by)
    return http
      .get<HistogramResult>("/events/histogram", { params, signal })
      .then(unwrap)
      .then(normalizeHistogram)
  },

  getEvent(uuid: string, signal?: AbortSignal): Promise<Event | null> {
    return http
      .get<Event>(`/events/${encodeURIComponent(uuid)}`, { signal })
      .then(unwrap)
      .then(normalizeEvent)
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

  /**
   * Creates (version 0) or updates an output; config is a patch, `null` clears a key. A saved output
   * whose destination did not answer comes back with a status that says why.
   */
  putOutput(name: string, version: number, config: Record<string, unknown>): Promise<SavedOutput> {
    return http
      .put<SavedOutput>(`/pipeline/outputs/${encodeURIComponent(name)}`, { version, config })
      .then(unwrap)
  },

  deleteOutput(name: string, version: number): Promise<void> {
    return http
      .delete(`/pipeline/outputs/${encodeURIComponent(name)}`, { params: { version } })
      .then(() => undefined)
  },

  getSecrets(signal?: AbortSignal): Promise<SecretsListing> {
    return http.get<SecretsListing>("/secrets", { signal }).then(unwrap)
  },

  getConfig(signal?: AbortSignal): Promise<MaskedConfig> {
    return http.get<MaskedConfig>("/config", { signal }).then(unwrap).then(normalizeConfig)
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
