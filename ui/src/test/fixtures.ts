import { AxiosError, AxiosHeaders, type AxiosAdapter, type InternalAxiosRequestConfig } from "axios"

import {
  normalizeOutputs,
  normalizePipeline,
  normalizeStatusList,
  type LayoutWire,
  type OutputsWire,
  type OutputTypesWire,
  type OutputTypeWire,
  type PipelineWire,
  type StatusListWire,
} from "@/lib/api-client"
import type {
  CountByResponse,
  Event,
  HistogramResult,
  MaskedConfig,
  OutputConfigEntry,
  SearchResult,
  VersionInfo,
} from "@/lib/types"

import configJson from "./fixtures/config.json"
import errorsJson from "./fixtures/errors.json"
import eventJson from "./fixtures/event.json"
import eventsCountByPriorityJson from "./fixtures/events-count-by-priority.json"
import eventsCountJson from "./fixtures/events-count.json"
import eventsHistogramJson from "./fixtures/events-histogram.json"
import eventsSearchJson from "./fixtures/events-search.json"
import layoutEmptyJson from "./fixtures/layout-empty.json"
import layoutJson from "./fixtures/layout.json"
import outputTypeJson from "./fixtures/output-type.json"
import outputTypesJson from "./fixtures/output-types.json"
import outputJson from "./fixtures/output.json"
import outputsJson from "./fixtures/outputs.json"
import pipelineStatusJson from "./fixtures/pipeline-status.json"
import pipelineJson from "./fixtures/pipeline.json"
import versionJson from "./fixtures/version.json"

type ErrorCase = { status: number; body: { error: string } }

// Golden responses written by internal/api/ui_contract_test.go (`go test ./internal/api/ -run
// TestUIContractFixtures -update`). JSON imports widen string unions, so each is cast to its wire type.
export const fixtures = {
  version: versionJson as VersionInfo,
  config: configJson as MaskedConfig,
  pipeline: pipelineJson as unknown as PipelineWire,
  pipelineStatus: pipelineStatusJson as unknown as StatusListWire,
  outputs: outputsJson as unknown as OutputsWire,
  output: outputJson as unknown as OutputConfigEntry,
  outputTypes: outputTypesJson as unknown as OutputTypesWire,
  outputType: outputTypeJson as unknown as OutputTypeWire,
  layout: layoutJson as LayoutWire,
  layoutEmpty: layoutEmptyJson as LayoutWire,
  eventsSearch: eventsSearchJson as unknown as SearchResult,
  eventsCount: eventsCountJson as { count: number },
  eventsCountByPriority: eventsCountByPriorityJson as CountByResponse,
  eventsHistogram: eventsHistogramJson as unknown as HistogramResult,
  event: eventJson as unknown as Event,
  errors: errorsJson as Record<keyof typeof errorsJson, ErrorCase>,
}

export const composite = normalizePipeline(structuredClone(fixtures.pipeline))
export const statuses = normalizeStatusList(structuredClone(fixtures.pipelineStatus).outputs)
export const outputs = normalizeOutputs(structuredClone(fixtures.outputs))
export const events = structuredClone(fixtures.eventsSearch).events

export function statusNamed(name: string) {
  const found = statuses.find((s) => s.name === name)
  if (!found) throw new Error(`no status fixture named ${name}`)
  return found
}

export function outputNamed(name: string) {
  const found = outputs.find((o) => o.name === name)
  if (!found) throw new Error(`no output fixture named ${name}`)
  return found
}

const ROUTES: Record<string, unknown> = {
  "GET /version": fixtures.version,
  "GET /config": fixtures.config,
  "GET /pipeline": fixtures.pipeline,
  "GET /pipeline/status": fixtures.pipelineStatus,
  "GET /pipeline/outputs": fixtures.outputs,
  "GET /pipeline/outputs/webhook": fixtures.output,
  "GET /pipeline/outputs/types": fixtures.outputTypes,
  "GET /pipeline/outputs/types/webhook": fixtures.outputType,
  "GET /pipeline/layout": fixtures.layout,
  "GET /events/search": fixtures.eventsSearch,
  "GET /events/count": fixtures.eventsCount,
  "GET /events/count/priority": fixtures.eventsCountByPriority,
  "GET /events/histogram": fixtures.eventsHistogram,
  [`GET /events/${fixtures.event.uuid}`]: fixtures.event,
}

export function routeKey(config: InternalAxiosRequestConfig): string {
  return `${(config.method ?? "get").toUpperCase()} ${(config.url ?? "").split("?")[0]}`
}

export function errorResponse(config: InternalAxiosRequestConfig, status: number, body: unknown): AxiosError {
  const response = { data: body, status, statusText: String(status), headers: {}, config }
  return new AxiosError(`Request failed with status code ${status}`, "ERR_BAD_RESPONSE", config, undefined, response)
}

export function networkError(config: InternalAxiosRequestConfig): AxiosError {
  return new AxiosError("Network Error", "ERR_NETWORK", config)
}

/** Serves the golden fixtures by method and path; unknown routes answer the 404 envelope. */
export function fixtureAdapter(calls: InternalAxiosRequestConfig[] = []): AxiosAdapter {
  return async (config) => {
    calls.push(config)
    const key = routeKey(config)
    if (!(key in ROUTES)) {
      throw errorResponse(config, fixtures.errors.not_found.status, fixtures.errors.not_found.body)
    }
    return {
      data: structuredClone(ROUTES[key]),
      status: 200,
      statusText: "OK",
      headers: {},
      config: { ...config, headers: config.headers ?? new AxiosHeaders() },
    }
  }
}
