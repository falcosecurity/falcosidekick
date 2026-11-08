import { afterEach, describe, expect, test } from "bun:test"
import userEvent from "@testing-library/user-event"
import { Route, Routes } from "react-router"

import { cleanup, renderWithProviders, screen } from "@/test/test-utils"

import { AppLayout } from "./layout"

afterEach(() => {
  cleanup()
  window.happyDOM.setViewport({ width: 1024, height: 800 })
})

function renderLayout() {
  return renderWithProviders(
    <Routes>
      <Route element={<AppLayout />}>
        <Route index element={<p>page body</p>} />
      </Route>
    </Routes>,
  )
}

describe("AppLayout", () => {
  test("offers a skip link as the first tab stop that lands on the main region", async () => {
    renderLayout()
    const user = userEvent.setup()
    await user.tab()
    const skip = screen.getByRole("link", { name: "Skip to main content" })
    expect(document.activeElement).toBe(skip)
    expect(skip).toHaveAttribute("href", "#main")
    expect(skip).toHaveClass("sr-only", "focus:not-sr-only")
    const main = screen.getByRole("main")
    expect(main).toHaveAttribute("id", "main")
    expect(main).toHaveAttribute("tabindex", "-1")
    expect(main).toHaveTextContent("page body")
  })

  test("exposes the banner, navigation and main landmarks", () => {
    renderLayout()
    expect(screen.getByRole("banner")).toBeInTheDocument()
    expect(screen.getByRole("navigation", { name: "Primary" })).toBeInTheDocument()
    expect(screen.getByRole("main")).toBeInTheDocument()
  })
})
