import { beforeEach, describe, expect, test } from "bun:test"

import { useUIStore } from "./ui-store"

function resetStore() {
  useUIStore.setState({
    sidebarCollapsed: false,
    sidebarOpen: false,
    refreshIntervalMs: 15_000,
  })
}

describe("ui-store", () => {
  beforeEach(() => {
    resetStore()
  })

  test("toggleSidebar flips the collapsed flag", () => {
    const initial = useUIStore.getState().sidebarCollapsed
    useUIStore.getState().toggleSidebar()
    expect(useUIStore.getState().sidebarCollapsed).toBe(!initial)
  })

  test("setSidebarOpen drives the navigation sheet without being persisted", () => {
    useUIStore.getState().setSidebarOpen(true)
    expect(useUIStore.getState().sidebarOpen).toBe(true)
    const persisted = JSON.parse(localStorage.getItem("falcosidekick-ui") ?? "{}") as { state?: Record<string, unknown> }
    expect(persisted.state).not.toHaveProperty("sidebarOpen")
    useUIStore.getState().setSidebarOpen(false)
    expect(useUIStore.getState().sidebarOpen).toBe(false)
  })

  test("setRefreshIntervalMs accepts 0 (off) and preset range", () => {
    useUIStore.getState().setRefreshIntervalMs(0)
    expect(useUIStore.getState().refreshIntervalMs).toBe(0)
    useUIStore.getState().setRefreshIntervalMs(30_000)
    expect(useUIStore.getState().refreshIntervalMs).toBe(30_000)
    useUIStore.getState().setRefreshIntervalMs(500)
    expect(useUIStore.getState().refreshIntervalMs).toBe(30_000)
    useUIStore.getState().setRefreshIntervalMs(900_000)
    expect(useUIStore.getState().refreshIntervalMs).toBe(30_000)
  })
})
