import { describe, expect, test } from "bun:test"

import { ApiError } from "./api-error"
import { createQueryClient, shouldRetry } from "./query-client"

describe("query retry policy", () => {
  test.each([400, 401, 403, 404, 409, 422, 503])("never retries a %s answer", (status) => {
    expect(shouldRetry(0, new ApiError(status, "no"))).toBe(false)
  })

  test.each([0, 500, 502, 504])("retries a %s answer twice", (status) => {
    const error = new ApiError(status, "transient")
    expect(shouldRetry(0, error)).toBe(true)
    expect(shouldRetry(1, error)).toBe(true)
    expect(shouldRetry(2, error)).toBe(false)
  })

  test("retries unknown errors twice", () => {
    expect(shouldRetry(0, new Error("boom"))).toBe(true)
    expect(shouldRetry(2, new Error("boom"))).toBe(false)
  })

  test("is installed as the default query retry", () => {
    const client = createQueryClient()
    expect(client.getDefaultOptions().queries?.retry).toBe(shouldRetry)
    expect(client.getDefaultOptions().mutations?.retry).toBe(0)
  })
})
