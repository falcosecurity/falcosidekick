import { afterEach, describe, expect, mock, test } from "bun:test"

import { useAuthStore } from "@/stores/auth-store"
import { act, cleanup, fireEvent, renderWithProviders, screen } from "@/test/test-utils"

import { LoginForm } from "./login-form"

const initialState = useAuthStore.getState()

afterEach(() => {
  cleanup()
  useAuthStore.setState(initialState)
})

describe("LoginForm", () => {
  test("uses a readable error foreground without changing the error tint", () => {
    useAuthStore.setState({ lastError: "Invalid username or password." })
    renderWithProviders(<LoginForm />)
    expect(screen.getByRole("alert")).toHaveTextContent("Invalid username or password.")
    expect(screen.getByRole("alert")).toHaveClass("text-status-error-foreground")
    expect(screen.getByRole("alert")).toHaveClass("bg-status-error/10", "border-status-error/30")
  })

  test("keeps fields and submit disabled and suppresses stale errors when authentication is disabled", () => {
    useAuthStore.setState({ lastError: "Previous login failed." })
    renderWithProviders(<LoginForm disabled />)
    expect(screen.getByLabelText("Username")).toBeDisabled()
    expect(screen.getByLabelText("Password")).toBeDisabled()
    expect(screen.getByRole("button", { name: "Sign in unavailable" })).toBeDisabled()
    expect(screen.queryByRole("alert")).toBeNull()
    expect(screen.getByLabelText("Username")).not.toHaveFocus()
  })

  test("does not submit populated credentials after authentication becomes disabled", async () => {
    const login = mock(async () => {})
    const onSuccess = mock(() => {})
    useAuthStore.setState({ login, lastError: null })
    const { container, rerender } = renderWithProviders(<LoginForm onSuccess={onSuccess} />)
    fireEvent.change(screen.getByLabelText("Username"), { target: { value: "operator" } })
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "test-password" } })
    rerender(<LoginForm disabled onSuccess={onSuccess} />)

    await act(async () => {
      fireEvent.submit(container.querySelector("form")!)
    })

    expect(login).not.toHaveBeenCalled()
    expect(onSuccess).not.toHaveBeenCalled()
  })
})
