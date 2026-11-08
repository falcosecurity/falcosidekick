import { afterEach, beforeEach, describe, expect, mock, spyOn, test } from "bun:test"
import ELK, { type ELK as ElkInstance, type ElkNode } from "elkjs/lib/elk.bundled.js"
import { createRef } from "react"

import type { OutputStatus, PipelineComposite } from "@/lib/types"
import { act, cleanup, fireEvent, renderWithProviders, screen, waitFor, within } from "@/test/test-utils"

import { PipelineCanvas, type PipelineCanvasHandle } from "./canvas"

const composite: PipelineComposite = {
  outputs: [{ name: "alerts", type: "webhook", config: {}, provisioned: true, version: 1, updated_at: "" }],
  status: [],
  layout: { nodes: [], edges: [], version: 1, updated_at: "" },
}

function status(state: OutputStatus["status"]): OutputStatus {
  return {
    name: "alerts", status: state, queue_depth: 0, queue_capacity: 100,
    sent_total: 0, failed_total: 0, dropped_total: 0,
    circuit_state: "closed", last_success: "", last_error: "",
  }
}

function positioned(graph: ElkNode, offset = 0): ElkNode {
  return {
    ...graph,
    children: graph.children?.map((node, i) => ({ ...node, x: i * 320 + offset, y: 20 })),
  }
}

function deferredLayout() {
  let resolve!: (value: ElkNode) => void
  const promise = new Promise<ElkNode>((resolvePromise) => { resolve = resolvePromise })
  return { promise, resolve }
}

const originalResizeObserver = window.ResizeObserver
const dimensionDescriptors = Object.getOwnPropertyDescriptors(HTMLElement.prototype)

class MeasuredResizeObserver extends originalResizeObserver {
  private callback: ResizeObserverCallback
  private targets = new Set<Element>()

  constructor(callback: ResizeObserverCallback) {
    super(callback)
    this.callback = callback
  }

  override observe(target: Element) {
    this.targets.add(target)
    queueMicrotask(() => {
      if (!this.targets.has(target)) return
      this.callback([{
        target, contentRect: target.getBoundingClientRect(),
        borderBoxSize: [], contentBoxSize: [], devicePixelContentBoxSize: [],
      }], this)
    })
  }

  override unobserve(target: Element) { this.targets.delete(target) }
  override disconnect() { this.targets.clear() }
}

let layoutSpy: ReturnType<typeof spyOn<ElkInstance, "layout">>

beforeEach(() => {
  window.ResizeObserver = MeasuredResizeObserver
  Object.defineProperties(HTMLElement.prototype, {
    offsetWidth: { configurable: true, get() { return this.classList.contains("react-flow__node") ? 230 : 1000 } },
    offsetHeight: { configurable: true, get() { return this.classList.contains("react-flow__node") ? 96 : 600 } },
  })
  layoutSpy = spyOn<ElkInstance, "layout">(ELK.prototype, "layout").mockImplementation(async (graph) => positioned(graph))
})

afterEach(() => {
  cleanup()
  layoutSpy.mockRestore()
  window.ResizeObserver = originalResizeObserver
  for (const key of ["offsetWidth", "offsetHeight"]) {
    const descriptor = dimensionDescriptors[key]
    if (descriptor) Object.defineProperty(HTMLElement.prototype, key, descriptor)
  }
})

async function edge(container: HTMLElement, id: string) {
  return waitFor(() => {
    const element = container.querySelector(`[data-testid="rf__edge-${id}"]`)
    expect(element).not.toBeNull()
    return element!
  })
}

describe("PipelineCanvas", () => {
  test("fits all nodes in a narrow container below the default zoom floor", async () => {
    Object.defineProperty(HTMLElement.prototype, "offsetWidth", {
      configurable: true,
      get() { return this.classList.contains("react-flow__node") ? 230 : 328 },
    })
    const { container } = renderWithProviders(
      <PipelineCanvas composite={composite} statusByName={{}} selection={null} onSelect={mock()} />,
    )
    await edge(container, "sidekick->alerts")
    fireEvent.click(screen.getByRole("button", { name: /fit view/i }))
    await waitFor(() => {
      const transform = container.querySelector<HTMLElement>(".react-flow__viewport")!.style.transform
      const zoom = Number(transform.match(/scale\(([^)]+)\)/)?.[1])
      expect(zoom).toBeGreaterThanOrEqual(0.1)
      expect(zoom * (640 + 230)).toBeLessThanOrEqual(328)
    })
  })

  test("polling updates both edge directions without re-running layout", async () => {
    const props = { composite, selection: null, onSelect: mock() }
    const { container, rerender } = renderWithProviders(
      <PipelineCanvas {...props} statusByName={{ alerts: status("idle") }} />,
    )
    expect(await edge(container, "falco->sidekick")).not.toHaveClass("animated")
    expect(await edge(container, "sidekick->alerts")).not.toHaveClass("animated")

    rerender(<PipelineCanvas {...props} statusByName={{ alerts: status("ok") }} />)
    await waitFor(() => {
      expect(container.querySelector('[data-testid="rf__edge-falco->sidekick"]')).toHaveClass("animated")
      expect(container.querySelector('[data-testid="rf__edge-sidekick->alerts"]')).toHaveClass("animated")
    })
    expect(screen.getByLabelText("status ok")).toBeInTheDocument()

    rerender(<PipelineCanvas {...props} statusByName={{ alerts: status("idle") }} />)
    await waitFor(() => {
      expect(container.querySelector('[data-testid="rf__edge-falco->sidekick"]')).not.toHaveClass("animated")
      expect(container.querySelector('[data-testid="rf__edge-sidekick->alerts"]')).not.toHaveClass("animated")
    })
    expect(layoutSpy).toHaveBeenCalledTimes(1)
  })

  test("a pending layout cannot overwrite newer status, selection or callback", async () => {
    const pending = deferredLayout()
    layoutSpy.mockImplementationOnce(() => pending.promise)
    const originalSelect = mock()
    const latestSelect = mock()
    const { container, rerender } = renderWithProviders(
      <PipelineCanvas composite={composite} statusByName={{ alerts: status("idle") }} selection={null} onSelect={originalSelect} />,
    )
    expect(container.querySelector(".pipeline-canvas")).toHaveAttribute("aria-busy", "true")
    rerender(
      <PipelineCanvas composite={composite} statusByName={{ alerts: status("ok") }} selection={{ kind: "sink", name: "alerts" }} onSelect={latestSelect} />,
    )
    await act(async () => pending.resolve(positioned(layoutSpy.mock.calls[0]![0])))
    const sink = await screen.findByRole("button", { name: /alerts webhook/ })
    expect(within(sink).getByLabelText("status ok")).toBeInTheDocument()
    expect(sink).toHaveClass("ring-brand")
    fireEvent.click(sink)
    expect(latestSelect).toHaveBeenCalledWith({ kind: "sink", name: "alerts" })
    expect(originalSelect).not.toHaveBeenCalled()
    expect(await edge(container, "sidekick->alerts")).toHaveClass("animated")
    expect(container.querySelector(".pipeline-canvas")).toHaveAttribute("aria-busy", "false")
  })

  test("a superseded topology cannot restore a removed output", async () => {
    const first = deferredLayout()
    const second = deferredLayout()
    layoutSpy.mockImplementationOnce(() => first.promise).mockImplementationOnce(() => second.promise)
    const props = { statusByName: {}, selection: null, onSelect: mock() }
    const { rerender } = renderWithProviders(<PipelineCanvas {...props} composite={composite} />)
    const replacement = { ...composite, outputs: [{ ...composite.outputs[0]!, name: "replacement" }] }
    rerender(<PipelineCanvas {...props} composite={replacement} />)
    await act(async () => second.resolve(positioned(layoutSpy.mock.calls[1]![0])))
    expect(await screen.findByRole("button", { name: "replacement webhook" })).toBeInTheDocument()
    await act(async () => first.resolve(positioned(layoutSpy.mock.calls[0]![0])))
    expect(screen.queryByRole("button", { name: "alerts webhook" })).not.toBeInTheDocument()
    expect(screen.getByRole("button", { name: "replacement webhook" })).toBeInTheDocument()
  })

  test("reset supersedes a pending layout", async () => {
    const first = deferredLayout()
    const second = deferredLayout()
    layoutSpy.mockImplementationOnce(() => first.promise).mockImplementationOnce(() => second.promise)
    const ref = createRef<PipelineCanvasHandle>()
    const { container } = renderWithProviders(
      <PipelineCanvas ref={ref} composite={composite} statusByName={{}} selection={null} onSelect={mock()} />,
    )
    act(() => ref.current?.resetPositions())
    await act(async () => second.resolve(positioned(layoutSpy.mock.calls[1]![0], 100)))
    await screen.findByRole("button", { name: "alerts webhook" })
    await act(async () => first.resolve(positioned(layoutSpy.mock.calls[0]![0])))
    expect(container.querySelector<HTMLElement>('[data-testid="rf__node-sink:alerts"]')?.style.transform).toBe("translate(740px,20px)")
  })

  test.each([false, true])("layout preserves a moved node when the drag has ended: %s", async (ended) => {
    const props = { statusByName: {}, selection: null, onSelect: mock() }
    const { container, rerender } = renderWithProviders(<PipelineCanvas {...props} composite={composite} />)
    await screen.findByRole("button", { name: "alerts webhook" })
    const sink = container.querySelector<HTMLElement>('[data-testid="rf__node-sink:alerts"]')!
    const flow = container.querySelector<HTMLElement>(".react-flow")!
    const bounds = spyOn(flow, "getBoundingClientRect").mockReturnValue(new DOMRect(0, 0, 1000, 600))
    const initialPosition = sink.style.transform
    const pending = deferredLayout()
    layoutSpy.mockImplementationOnce(() => pending.promise)
    const expanded = {
      ...composite,
      outputs: [...composite.outputs, { ...composite.outputs[0]!, name: "new-output" }],
    }
    rerender(<PipelineCanvas {...props} composite={expanded} />)

    fireEvent.mouseDown(sink, { view: window, button: 0, buttons: 1, clientX: 400, clientY: 200 })
    try {
      fireEvent.mouseMove(window, { view: window, buttons: 1, clientX: 430, clientY: 220 })
      fireEvent.mouseMove(window, { view: window, buttons: 1, clientX: 460, clientY: 240 })
      expect(sink).toHaveClass("dragging")
      const draggedPosition = sink.style.transform
      expect(draggedPosition).not.toBe(initialPosition)
      if (ended) fireEvent.mouseUp(window, { view: window, button: 0, clientX: 460, clientY: 240 })

      await act(async () => pending.resolve(positioned(layoutSpy.mock.calls[1]![0], 100)))
      expect(sink.style.transform).toBe(draggedPosition)
      expect(sink.classList.contains("dragging")).toBe(!ended)
      expect(await screen.findByRole("button", { name: "new-output webhook" })).toBeInTheDocument()

      if (!ended) {
        const nextLayout = deferredLayout()
        layoutSpy.mockImplementationOnce(() => nextLayout.promise)
        rerender(<PipelineCanvas {...props} composite={{
          ...expanded,
          outputs: [...expanded.outputs, { ...composite.outputs[0]!, name: "another-output" }],
        }} />)
        await act(async () => nextLayout.resolve(positioned(layoutSpy.mock.calls[2]![0], 200)))
        expect(sink.style.transform).toBe(draggedPosition)
        expect(sink).toHaveClass("dragging")
        fireEvent.mouseMove(window, { view: window, buttons: 1, clientX: 490, clientY: 260 })
        expect(sink.style.transform).not.toBe(draggedPosition)
      }
    } finally {
      fireEvent.mouseUp(window, { view: window, button: 0, clientX: 490, clientY: 260 })
      bounds.mockRestore()
    }
    expect(sink).not.toHaveClass("dragging")
  })

  test("unmount discards a pending layout completion", async () => {
    const pending = deferredLayout()
    layoutSpy.mockImplementationOnce(() => pending.promise)
    const ref = createRef<PipelineCanvasHandle>()
    const { container, unmount } = renderWithProviders(
      <PipelineCanvas ref={ref} composite={composite} statusByName={{}} selection={null} onSelect={mock()} />,
    )
    expect(container.querySelector(".pipeline-canvas")).toHaveAttribute("aria-busy", "true")
    unmount()
    await act(async () => pending.resolve(positioned(layoutSpy.mock.calls[0]![0])))
    expect(container.childElementCount).toBe(0)
    expect(ref.current).toBeNull()
    expect(layoutSpy).toHaveBeenCalledTimes(1)
  })

  test("layout preserves measured dimensions of existing nodes", async () => {
    const observe = spyOn(MeasuredResizeObserver.prototype, "observe")
    try {
      const props = { statusByName: {}, selection: null, onSelect: mock() }
      const { container, rerender } = renderWithProviders(<PipelineCanvas {...props} composite={composite} />)
      await edge(container, "sidekick->alerts")
      const sink = container.querySelector('[data-testid="rf__node-sink:alerts"]')!
      const measurementsBefore = observe.mock.calls.filter(([target]) => target === sink).length
      expect(measurementsBefore).toBeGreaterThan(0)
      const pending = deferredLayout()
      layoutSpy.mockImplementationOnce(() => pending.promise)
      rerender(<PipelineCanvas {...props} composite={{
        ...composite,
        outputs: [...composite.outputs, { ...composite.outputs[0]!, name: "new-output" }],
      }} />)
      await act(async () => pending.resolve(positioned(layoutSpy.mock.calls[1]![0], 100)))
      expect(await screen.findByRole("button", { name: "new-output webhook" })).toBeInTheDocument()
      expect(observe.mock.calls.filter(([target]) => target === sink)).toHaveLength(measurementsBefore)
      expect(sink).toBeVisible()
    } finally {
      observe.mockRestore()
    }
  })

  test("layout failure is visible and reset can retry", async () => {
    layoutSpy.mockRejectedValueOnce(new Error("layout failed"))
    const ref = createRef<PipelineCanvasHandle>()
    const { container } = renderWithProviders(
      <PipelineCanvas ref={ref} composite={composite} statusByName={{}} selection={null} onSelect={mock()} />,
    )
    expect(await screen.findByText("Unable to lay out pipeline")).toBeInTheDocument()
    expect(container.querySelector(".pipeline-canvas")).toHaveAttribute("aria-busy", "false")
    act(() => ref.current?.resetPositions())
    expect(await screen.findByRole("button", { name: "alerts webhook" })).toBeInTheDocument()
    expect(screen.queryByText("Unable to lay out pipeline")).not.toBeInTheDocument()
  })

  test("an empty output set retains the source and core with a non-flowing edge", async () => {
    const { container } = renderWithProviders(
      <PipelineCanvas composite={{ ...composite, outputs: [] }} statusByName={{ alerts: status("ok") }} selection={null} onSelect={mock()} />,
    )
    expect(await screen.findByRole("button", { name: "Falco event source" })).toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Falco Sidekick event pipeline" })).toBeInTheDocument()
    expect(await edge(container, "falco->sidekick")).not.toHaveClass("animated")
    expect(container.querySelectorAll(".react-flow__node")).toHaveLength(2)
  })

  test("the real ELK engine positions a source, core and sink from left to right", async () => {
    layoutSpy.mockRestore()
    const { container } = renderWithProviders(
      <PipelineCanvas composite={composite} statusByName={{}} selection={null} onSelect={mock()} />,
    )
    await screen.findByRole("button", { name: "alerts webhook" })
    const positions = ["source:falco", "core:sidekick", "sink:alerts"].map((id) => {
      const transform = container.querySelector<HTMLElement>(`[data-testid="rf__node-${id}"]`)!.style.transform
      return Number(transform.match(/translate\(([-\d.]+)px/)![1])
    })
    expect(positions[1]!).toBeGreaterThan(positions[0]!)
    expect(positions[2]!).toBeGreaterThan(positions[1]!)
  })
})
