import { afterEach, describe, expect, mock, test } from "bun:test"
import type { InternalAxiosRequestConfig } from "axios"

import { setApiAdapterForTests } from "@/lib/api-client"
import { errorResponse, fixtures } from "@/test/fixtures"
import { cleanup, fireEvent, renderWithProviders, screen, waitFor } from "@/test/test-utils"

import { DeleteOutputDialog } from "./delete-output-dialog"

afterEach(() => {
  cleanup()
  setApiAdapterForTests(null)
})

describe("DeleteOutputDialog", () => {
  test("removes with the version read, then reports it", async () => {
    const calls: InternalAxiosRequestConfig[] = []
    setApiAdapterForTests(async (config) => {
      calls.push(config)
      return { data: "", status: 204, statusText: "No Content", headers: {}, config }
    })
    const onDeleted = mock()
    const onClose = mock()
    renderWithProviders(<DeleteOutputDialog entry={fixtures.output} onClose={onClose} onDeleted={onDeleted} />)
    expect(screen.getByRole("alertdialog", { name: "Remove Webhook?" })).toBeInTheDocument()
    fireEvent.click(screen.getByRole("button", { name: "Remove" }))
    await waitFor(() => expect(onDeleted).toHaveBeenCalledWith("webhook"))
    expect(calls[0]?.method).toBe("delete")
    expect(calls[0]?.url).toBe("/pipeline/outputs/webhook")
    expect(calls[0]?.params).toEqual({ version: fixtures.output.version })
    expect(onClose).toHaveBeenCalled()
  })

  test("a stale version is not removed and the dialog closes", async () => {
    setApiAdapterForTests(async (config) => {
      throw errorResponse(config, 409, fixtures.errors.version_conflict.body)
    })
    const onDeleted = mock()
    const onClose = mock()
    renderWithProviders(<DeleteOutputDialog entry={fixtures.output} onClose={onClose} onDeleted={onDeleted} />)
    fireEvent.click(screen.getByRole("button", { name: "Remove" }))
    await waitFor(() => expect(onClose).toHaveBeenCalled())
    expect(onDeleted).not.toHaveBeenCalled()
  })

  test("warns that an output from the files comes back at the next reload", () => {
    setApiAdapterForTests(async (config) => ({ data: "", status: 204, statusText: "", headers: {}, config }))
    renderWithProviders(<DeleteOutputDialog entry={{ ...fixtures.output, provisioned: true }} onClose={mock()} />)
    expect(screen.getByText(/comes back at the next reload/)).toBeInTheDocument()
  })
})
