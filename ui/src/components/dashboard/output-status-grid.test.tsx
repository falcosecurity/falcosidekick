import { afterEach, describe, expect, test } from "bun:test"
import { QueryClient } from "@tanstack/react-query"

import type { OutputStatus, PipelineComposite } from "@/lib/types"
import { usePipelineStore } from "@/stores/pipeline-store"
import { REFRESH_OPTIONS, useUIStore } from "@/stores/ui-store"
import { cleanup, renderWithProviders, screen, within } from "@/test/test-utils"

import { OutputStatusGrid } from "./output-status-grid"

const status: OutputStatus = {
  name: "alerts",
  status: "degraded",
  queue_depth: 80,
  queue_capacity: 100,
  sent_total: 12,
  dropped_total: 3,
  failed_total: 2,
  events_per_minute: 10,
  circuit_state: "open",
  last_success: "2026-10-05T12:00:00Z",
  last_error: "upstream unavailable",
}

const composite: PipelineComposite = {
  outputs: [{ name: "alerts", type: "webhook", config: {}, provisioned: true, version: 1, updated_at: "" }],
  status: [status],
  layout: { version: 1, updated_at: "", nodes: [], edges: [] },
}

const clients: QueryClient[] = []
const initialUIState = useUIStore.getState()
const initialPipelineState = usePipelineStore.getState()

function renderGrid(statusList?: OutputStatus[], error?: Error) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { enabled: false, retry: false, gcTime: 0 } },
  })
  clients.push(queryClient)
  queryClient.setQueryData(["pipeline", "composite"], composite)
  if (statusList) queryClient.setQueryData(["pipeline", "status"], statusList)
  if (error) {
    queryClient.getQueryCache().build(queryClient, { queryKey: ["pipeline", "status"] }).setState({
      status: "error",
      error,
    })
  }
  return renderWithProviders(<OutputStatusGrid />, { queryClient })
}

afterEach(() => {
  cleanup()
  for (const client of clients.splice(0)) client.clear()
  useUIStore.setState(initialUIState)
  usePipelineStore.setState(initialPipelineState)
})

describe("OutputStatusGrid", () => {
  test.each(REFRESH_OPTIONS)("does not claim a fixed refresh cadence with $label selected", ({ value }) => {
    useUIStore.setState({ refreshIntervalMs: value })
    renderGrid([status])
    expect(screen.getByText("Output status")).toBeInTheDocument()
    expect(screen.queryByText(/refreshes every/i)).not.toBeInTheDocument()
  })

  test("renders loading state before status is available", () => {
    renderGrid()
    expect(screen.getAllByRole("status")).toHaveLength(3)
    for (const skeleton of screen.getAllByRole("status")) {
      expect(skeleton).toHaveAttribute("aria-busy", "true")
    }
    expect(screen.queryByText("No outputs configured")).not.toBeInTheDocument()
  })

  test("renders an error instead of an empty list", () => {
    renderGrid(undefined, new Error("offline"))
    expect(screen.getByText("Unable to load output status")).toBeInTheDocument()
    expect(screen.queryByText("No outputs configured")).not.toBeInTheDocument()
  })

  test("renders an empty state for no configured outputs", () => {
    renderGrid([])
    expect(screen.getByText("No outputs configured")).toBeInTheDocument()
  })

  test("renders output metrics, status, circuit and error with readable foregrounds", () => {
    renderGrid([status])
    expect(screen.getByText("alerts")).toBeInTheDocument()
    expect(screen.getByText("webhook")).toBeInTheDocument()
    expect(screen.getByRole("status", { name: "status degraded" })).toHaveTextContent("degraded")
    expect(screen.getByText("12")).toHaveClass("text-status-ok-foreground")
    expect(screen.getByText("2")).toHaveClass("text-status-error-foreground")
    expect(screen.getByText("3")).toHaveClass("text-status-degraded-foreground")
    expect(screen.getByText("80/100")).toHaveClass("text-status-degraded-foreground")
    expect(screen.getByText("circuit: open")).toHaveClass("text-status-degraded-foreground")
    expect(screen.getByText("upstream unavailable")).toHaveClass("text-status-error-foreground")
  })

  test("keeps all zero-valued metrics in a labelled group", () => {
    renderGrid([{
      ...status,
      status: "idle",
      sent_total: 0,
      failed_total: 0,
      dropped_total: 0,
      queue_depth: 0,
      queue_capacity: 0,
      events_per_minute: 0,
      circuit_state: "closed",
      last_error: "",
    }])

    const metrics = screen.getByText("Sent").closest("dl")
    expect(metrics).not.toBeNull()
    const group = within(metrics!)
    expect(group.getAllByRole("term").map((term) => term.textContent)).toEqual([
      "Sent", "Failed", "Dropped", "Queue",
    ])
    expect(group.getAllByRole("definition").map((value) => value.textContent)).toEqual([
      "0", "0", "0", "0/0",
    ])
    expect(screen.getByText("0 evt/min")).toBeInTheDocument()
    expect(screen.getByRole("status", { name: "status idle" })).toBeInTheDocument()
    expect(screen.queryByText(/circuit:/)).toBeNull()
    expect(screen.queryByText("upstream unavailable")).toBeNull()
  })

  test.each([
    { depth: 0, capacity: 100, width: "0%", tone: "text-foreground" },
    { depth: 0, capacity: 0, width: "0%", tone: "text-foreground" },
    { depth: 10, capacity: 0, width: "0%", tone: "text-foreground" },
    { depth: 75, capacity: 100, width: "75%", tone: "text-foreground" },
    { depth: 76, capacity: 100, width: "76%", tone: "text-status-degraded-foreground" },
    { depth: 120, capacity: 100, width: "100%", tone: "text-status-degraded-foreground" },
  ])("renders queue $depth/$capacity without fabricated occupancy", ({ depth, capacity, width, tone }) => {
    renderGrid([{ ...status, queue_depth: depth, queue_capacity: capacity }])
    const value = screen.getByText(`${depth}/${capacity}`)
    expect(value).toHaveClass(tone)
    const fill = value.parentElement!.querySelector<HTMLElement>('[aria-hidden="true"] > div')
    expect(fill).not.toBeNull()
    expect(fill!.style.width).toBe(width)
  })
})
