import { afterEach, beforeEach, describe, expect, spyOn, test } from "bun:test"
import ELK, { type ELK as ElkInstance } from "elkjs/lib/elk.bundled.js"

import * as Resizable from "@/components/ui/resizable"
import { api } from "@/lib/api-client"
import type { PipelineComposite } from "@/lib/types"
import { usePipelineStore } from "@/stores/pipeline-store"
import { act, cleanup, renderWithProviders, screen } from "@/test/test-utils"

import { PipelinePage } from "./pipeline"

const composite: PipelineComposite = {
  outputs: [], status: [], layout: { nodes: [], edges: [], version: 1, updated_at: "" },
}
const originalResizeObserver = window.ResizeObserver
const observers: PageResizeObserver[] = []

class PageResizeObserver extends originalResizeObserver {
  readonly targets = new Set<Element>()
  disconnected = false
  private callback: ResizeObserverCallback

  constructor(callback: ResizeObserverCallback) {
    super(callback)
    this.callback = callback
    observers.push(this)
  }

  override observe(target: Element) { this.targets.add(target) }
  override unobserve(target: Element) { this.targets.delete(target) }
  override disconnect() { this.disconnected = true; this.targets.clear() }

  resize(target: Element, width: number) {
    this.callback([{
      target, contentRect: new DOMRect(0, 0, width, 700),
      borderBoxSize: [], contentBoxSize: [], devicePixelContentBoxSize: [],
    }], this)
  }
}

let pipelineSpy: ReturnType<typeof spyOn<typeof api, "getPipeline">>
let statusSpy: ReturnType<typeof spyOn<typeof api, "getPipelineStatus">>
let layoutSpy: ReturnType<typeof spyOn<ElkInstance, "layout">>
let originalStore: ReturnType<typeof usePipelineStore.getState>
let panelSpy: ReturnType<typeof spyOn<typeof Resizable, "ResizablePanel">>

beforeEach(() => {
  originalStore = usePipelineStore.getState()
  panelSpy = spyOn(Resizable, "ResizablePanel")
  observers.length = 0
  window.ResizeObserver = PageResizeObserver
  pipelineSpy = spyOn(api, "getPipeline").mockResolvedValue(composite)
  statusSpy = spyOn(api, "getPipelineStatus").mockResolvedValue([])
  layoutSpy = spyOn<ElkInstance, "layout">(ELK.prototype, "layout").mockImplementation(() => new Promise(() => {}))
})

afterEach(() => {
  cleanup()
  pipelineSpy.mockRestore()
  statusSpy.mockRestore()
  layoutSpy.mockRestore()
  panelSpy.mockRestore()
  window.ResizeObserver = originalResizeObserver
  usePipelineStore.setState(originalStore, true)
})

function pageObserver(target: Element) {
  const observer = observers.find((candidate) => candidate.targets.has(target))
  expect(observer).toBeDefined()
  return observer!
}

describe("PipelinePage responsive layout", () => {
  test.each([232, 302, 488, 1152])("keeps usable panel minimums at container width %s", async (width) => {
    const { container } = renderWithProviders(<PipelinePage />)
    const wrapper = container.firstElementChild!
    act(() => pageObserver(wrapper).resize(wrapper, width))
    const group = await screen.findByTestId("pipeline-layout")
    const stacked = width < 900
    expect(group).toHaveClass(stacked ? "min-h-[800px]" : "min-h-0")
    const [canvas, details] = panelSpy.mock.calls.slice(-2).map(([props]) => props)
    expect(canvas?.defaultSize).toBe(stacked ? "50%" : "70%")
    expect(canvas?.minSize).toBe(stacked ? "300px" : "320px")
    expect(details?.defaultSize).toBe(stacked ? "50%" : "30%")
    expect(details?.minSize).toBe(stacked ? "440px" : "280px")
  })

  test("uses the container width to stack panels without remounting the canvas", async () => {
    const { container } = renderWithProviders(<PipelinePage />)
    const wrapper = container.firstElementChild!
    const observer = pageObserver(wrapper)
    const group = await screen.findByTestId("pipeline-layout")
    const canvas = container.querySelector(".pipeline-canvas")

    act(() => observer.resize(wrapper, 488))
    expect(group.style.flexDirection).toBe("column")
    expect(screen.getByRole("separator")).toHaveAttribute("aria-orientation", "horizontal")
    act(() => observer.resize(wrapper, 1152))
    expect(group.style.flexDirection).toBe("row")
    expect(screen.getByRole("separator")).toHaveAttribute("aria-orientation", "vertical")
    act(() => observer.resize(wrapper, 488))
    expect(group.style.flexDirection).toBe("column")
    expect(container.querySelector(".pipeline-canvas")).toBe(canvas)
    expect(layoutSpy).toHaveBeenCalledTimes(1)
    expect(pageObserver(wrapper)).toBe(observer)
  })

  test("observes the same wrapper across loading and ignores zero-size notifications", async () => {
    let resolve!: (value: PipelineComposite) => void
    pipelineSpy.mockImplementationOnce(() => new Promise((done) => { resolve = done }))
    const { container } = renderWithProviders(<PipelinePage />)
    const wrapper = container.firstElementChild!
    const observer = pageObserver(wrapper)
    expect(screen.queryByTestId("pipeline-layout")).not.toBeInTheDocument()
    act(() => observer.resize(wrapper, 1152))
    await act(async () => resolve(composite))
    const group = await screen.findByTestId("pipeline-layout")
    expect(group.style.flexDirection).toBe("row")
    act(() => observer.resize(wrapper, 0))
    expect(group.style.flexDirection).toBe("row")
    expect(container.firstElementChild).toBe(wrapper)
    expect(pageObserver(wrapper)).toBe(observer)
  })

  test("disconnects on unmount and tolerates an already queued resize notification", async () => {
    const { container, unmount } = renderWithProviders(<PipelinePage />)
    const wrapper = container.firstElementChild!
    const observer = pageObserver(wrapper)
    await screen.findByTestId("pipeline-layout")
    unmount()
    expect(observer.disconnected).toBe(true)
    expect(observer.targets.size).toBe(0)
    act(() => observer.resize(wrapper, 1152))
    expect(container).toBeEmptyDOMElement()
  })
})
