import { afterEach, beforeEach, describe, expect, spyOn, test } from "bun:test"
import { QueryClient } from "@tanstack/react-query"
import userEvent from "@testing-library/user-event"

import { useUIStore } from "@/stores/ui-store"
import { act, cleanup, renderWithProviders, screen } from "@/test/test-utils"

import { TopBar } from "./top-bar"

let originalStore: ReturnType<typeof useUIStore.getState>

beforeEach(() => {
  originalStore = useUIStore.getState()
  useUIStore.setState({ authEnabled: false, sidebarCollapsed: true, refreshIntervalMs: 0 })
})

afterEach(() => {
  cleanup()
  useUIStore.setState(originalStore, true)
})

describe("TopBar responsive controls", () => {
  test("uses two stable mobile rows and one desktop row without hiding commands", () => {
    renderWithProviders(<TopBar />, { initialEntries: ["/pipeline"] })
    const toggle = screen.getByRole("button", { name: "Toggle navigation sidebar" })
    const grid = toggle.parentElement!
    expect(grid).toHaveClass("grid", "h-24", "grid-rows-2", "grid-cols-[auto_minmax(0,1fr)]", "px-2")
    expect(grid).toHaveClass("sm:h-14", "sm:grid-rows-1", "sm:grid-cols-[auto_minmax(0,1fr)_auto]", "sm:px-4")
    expect(screen.getByText("Pipeline")).toHaveClass("min-w-0", "truncate")
    const controls = screen.getByRole("button", { name: "Switch to dark theme" }).parentElement!
    expect(controls).toHaveClass("col-span-2", "sm:col-span-1", "gap-1", "sm:gap-2")
    expect(controls).toContainElement(screen.getByRole("button", { name: "Refresh all data now" }))
    expect(controls).toContainElement(screen.getByRole("combobox", { name: "Auto-refresh interval" }))
    expect(controls).toContainElement(screen.getByLabelText(/Authentication disabled/))
    expect(controls.parentElement).toBe(grid)
    expect(screen.getByRole("button", { name: "Switch to dark theme" })).toBeVisible()
  })

  test("the navigation command still toggles the sidebar", async () => {
    renderWithProviders(<TopBar />)
    const user = userEvent.setup()
    await user.click(screen.getByRole("button", { name: "Toggle navigation sidebar" }))
    expect(useUIStore.getState().sidebarCollapsed).toBe(false)
    await user.click(screen.getByRole("button", { name: "Toggle navigation sidebar" }))
    expect(useUIStore.getState().sidebarCollapsed).toBe(true)
  })

  test("the grouped refresh command still invalidates queries", async () => {
    const queryClient = new QueryClient()
    const invalidate = spyOn(queryClient, "invalidateQueries")
    try {
      renderWithProviders(<TopBar />, { queryClient })
      await userEvent.setup().click(screen.getByRole("button", { name: "Refresh all data now" }))
      expect(invalidate).toHaveBeenCalledTimes(1)
    } finally {
      invalidate.mockRestore()
    }
  })

  test("auth-state updates preserve both the control group and its theme command", () => {
    renderWithProviders(<TopBar />)
    const theme = screen.getByRole("button", { name: "Switch to dark theme" })
    const controls = theme.parentElement
    act(() => useUIStore.setState({ authEnabled: true }))
    expect(screen.queryByLabelText(/Authentication disabled/)).not.toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Switch to dark theme" })).toBe(theme)
    act(() => useUIStore.setState({ authEnabled: false }))
    expect(controls).toContainElement(screen.getByLabelText(/Authentication disabled/))
  })
})
