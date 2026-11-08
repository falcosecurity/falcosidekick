import { afterEach, describe, expect, test } from "bun:test"

import { useUIStore } from "@/stores/ui-store"
import { cleanup, renderWithProviders, screen } from "@/test/test-utils"

import { AuthDisabledBanner } from "./auth-disabled-banner"

const initialState = useUIStore.getState()

afterEach(() => {
  cleanup()
  useUIStore.setState(initialState)
})

describe("AuthDisabledBanner", () => {
  test.each([false, true])("uses a readable foreground when compact=%s", (compact) => {
    useUIStore.setState({ authEnabled: false })
    renderWithProviders(<AuthDisabledBanner compact={compact} />)
    const banner = compact
      ? screen.getByLabelText(/Authentication disabled/)
      : screen.getByRole("status")
    expect(banner).toHaveClass("text-status-degraded-foreground")
    expect(banner).toHaveClass("bg-status-degraded/10", "border-status-degraded/30")
    expect(banner).toHaveTextContent(compact ? "Auth off" : "API is unauthenticated")
  })

  test.each([true, null])("does not declare authentication disabled when enabled=%s", (authEnabled) => {
    useUIStore.setState({ authEnabled })
    const { container } = renderWithProviders(<AuthDisabledBanner />)
    expect(container).toBeEmptyDOMElement()
  })
})
