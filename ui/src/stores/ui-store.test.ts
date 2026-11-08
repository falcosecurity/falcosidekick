import { beforeEach, describe, expect, test } from "bun:test"

import { useUIStore } from "./ui-store"

function resetStore() {
  useUIStore.setState({
    sidebarCollapsed: false,
    refreshIntervalMs: 15_000,
    authEnabled: null,
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

  test("setAuthEnabled accepts tri-state", () => {
    const set = useUIStore.getState().setAuthEnabled
    set(true)
    expect(useUIStore.getState().authEnabled).toBe(true)
    set(false)
    expect(useUIStore.getState().authEnabled).toBe(false)
    set(null)
    expect(useUIStore.getState().authEnabled).toBeNull()
  })
})
