import { afterEach, describe, expect, test } from "bun:test"
import { QueryClient } from "@tanstack/react-query"

import type { OutputStatus } from "@/lib/types"
import { usePipelineStore } from "@/stores/pipeline-store"
import { REFRESH_OPTIONS, useUIStore } from "@/stores/ui-store"
import { statusNamed, statuses } from "@/test/fixtures"
import { cleanup, renderWithProviders, screen, within } from "@/test/test-utils"

import { OutputStatusGrid, queueTone } from "./output-status-grid"

const ok = statusNamed("inmemory")
const failing = statusNamed("webhook")
const notRunning = statusNamed("alertmanager")

const clients: QueryClient[] = []
const initialUIState = useUIStore.getState()
const initialPipelineState = usePipelineStore.getState()

function renderGrid(statusList?: OutputStatus[], error?: Error) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { enabled: false, retry: false, gcTime: 0 } },
  })
  clients.push(queryClient)
  if (statusList) queryClient.setQueryData(["pipeline", "status"], statusList)
  if (error) {
    queryClient.getQueryCache().build(queryClient, { queryKey: ["pipeline", "status"] }).setState({
      status: "error",
      error,
    })
  }
  return renderWithProviders(<OutputStatusGrid />, { queryClient })
}

function row(name: string) {
  return screen.getByRole("heading", { level: 3, name }).closest("li")!
}

function statusBadge(scope: HTMLElement, status: string) {
  return within(scope).getByText(status, { selector: "[data-status]" })
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
    renderGrid(statuses)
    expect(screen.getByRole("heading", { level: 2, name: "Output status" })).toBeInTheDocument()
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

  test("renders the backend error text instead of an empty list", () => {
    renderGrid(undefined, new Error("database unavailable"))
    expect(screen.getByText("Unable to load output status")).toBeInTheDocument()
    expect(screen.getByText("database unavailable")).toBeInTheDocument()
    expect(screen.queryByText("No outputs configured")).not.toBeInTheDocument()
  })

  test("renders an empty state for no configured outputs", () => {
    renderGrid([])
    expect(screen.getByText("No outputs configured")).toBeInTheDocument()
  })

  test("renders every output of the backend fixture with its driver icon and no live regions", () => {
    renderGrid(statuses)
    expect(screen.getAllByRole("heading", { level: 3 }).map((h) => h.textContent)).toEqual([
      "alertmanager", "inmemory", "webhook",
    ])
    for (const s of statuses) {
      expect(row(s.name).querySelector(`[data-driver="${s.name}"]`)).not.toBeNull()
      expect(statusBadge(row(s.name), s.status)).toBeInTheDocument()
    }
    expect(screen.queryByRole("status")).toBeNull()
  })

  test("a delivering output shows its last success as a relative time", () => {
    renderGrid([ok])
    const r = row("inmemory")
    expect(within(r).getByText("3 evt/min")).toBeInTheDocument()
    expect(within(r).getByText(/^last success/).querySelector("time")).not.toBeNull()
    expect(within(r).getByRole("meter", { name: "Queue inmemory" })).toHaveAttribute("aria-valuemax", "100")
    expect(within(r).queryByText(/circuit:/)).toBeNull()
  })

  test("an output that never delivered says so and shows its error", () => {
    renderGrid([failing])
    const r = row("webhook")
    expect(within(r).getByText(/^last success/)).toHaveTextContent("last success never")
    expect(within(r).getByText("connection refused")).toHaveClass("text-status-error-foreground")
    expect(within(within(r).getByText("Failed").parentElement!).getByRole("definition")).toHaveClass("text-status-error-foreground")
  })

  test("an output that is not running has no circuit and a dashed failed badge", () => {
    renderGrid([notRunning])
    const r = row("alertmanager")
    expect(statusBadge(r, "failed")).toHaveClass("border-dashed")
    expect(within(r).queryByText(/circuit:/)).toBeNull()
    expect(within(r).getByText(notRunning.last_error)).toBeInTheDocument()
    expect(within(r).getByRole("meter", { name: "Queue alertmanager" })).toHaveAttribute("aria-valuemax", "0")
  })

  test("renders a warning of a degraded output that still delivers", () => {
    renderGrid([{
      ...ok,
      status: "degraded",
      circuit_state: "open",
      last_warning: "1 of 2 hosts failed: connection refused",
    }])
    const r = row("inmemory")
    expect(statusBadge(r, "degraded")).toBeInTheDocument()
    expect(within(r).getByText("circuit: open")).toHaveClass("text-status-degraded-foreground")
    expect(within(r).getByText("1 of 2 hosts failed: connection refused")).toHaveClass("text-status-degraded-foreground")
  })

  test("keeps all zero-valued metrics in a labelled group", () => {
    renderGrid([{ ...ok, status: "idle", sent_total: 0, queue_capacity: 0, events_per_minute: 0 }])
    const metrics = screen.getByText("Sent").closest("dl")!
    expect(within(metrics).getAllByRole("term").map((term) => term.textContent)).toEqual(["Sent", "Failed", "Dropped", "Queue"])
    expect(within(metrics).getAllByRole("definition").map((value) => value.textContent)).toEqual(["0", "0", "0", "0/0"])
    expect(screen.getByText("0 evt/min")).toBeInTheDocument()
  })

  test.each([
    { depth: 0, capacity: 100, width: "0%", tone: "neutral" },
    { depth: 10, capacity: 0, width: "0%", tone: "neutral" },
    { depth: 75, capacity: 100, width: "75%", tone: "neutral" },
    { depth: 76, capacity: 100, width: "76%", tone: "warning" },
    { depth: 120, capacity: 100, width: "100%", tone: "warning" },
  ])("renders queue $depth/$capacity as a meter without fabricated occupancy", ({ depth, capacity, width, tone }) => {
    renderGrid([{ ...ok, queue_depth: depth, queue_capacity: capacity }])
    expect(queueTone(depth, capacity)).toBe(tone)
    const meter = screen.getByRole("meter", { name: "Queue inmemory" })
    expect((meter.firstElementChild as HTMLElement).style.width).toBe(width)
    expect(meter.firstElementChild).toHaveClass(tone === "warning" ? "bg-status-degraded" : "bg-brand/70")
    expect(screen.getByText(`${depth}/${capacity}`)).toHaveClass(
      tone === "warning" ? "text-status-degraded-foreground" : "text-foreground",
    )
  })
})
