import { afterEach, describe, expect, test } from "bun:test"
import { QueryClient } from "@tanstack/react-query"
import type { InternalAxiosRequestConfig } from "axios"

import { setApiAdapterForTests } from "@/lib/api-client"
import { fixtureAdapter, fixtures } from "@/test/fixtures"
import { cleanup, renderWithProviders, screen, waitFor } from "@/test/test-utils"

import { useConfig, useVersion } from "./use-config"

afterEach(() => {
  cleanup()
  setApiAdapterForTests(null)
})

function Probe() {
  const config = useConfig()
  const version = useVersion()
  if (!config.data || !version.data) return <p>loading</p>
  return (
    <p>
      {`${config.data.config.listen_port} ${version.data.version} ${version.data.build_date} ${version.data.go_version}`}
    </p>
  )
}

describe("useConfig and useVersion", () => {
  test("fetch once per client and never go stale", async () => {
    const calls: InternalAxiosRequestConfig[] = []
    setApiAdapterForTests(fixtureAdapter(calls))
    const client = new QueryClient()
    const { rerender, unmount } = renderWithProviders(<Probe />, { queryClient: client })
    await screen.findByText(`2801 ${fixtures.version.version} ${fixtures.version.build_date} ${fixtures.version.go_version}`)

    rerender(<Probe />)
    unmount()
    renderWithProviders(<Probe />, { queryClient: client })
    await screen.findByText(/2801/)
    await waitFor(() => expect(calls.filter((c) => c.url === "/config")).toHaveLength(1))
    expect(calls.filter((c) => c.url === "/version")).toHaveLength(1)

    for (const key of [["config"], ["version"]]) {
      const query = client.getQueryCache().find({ queryKey: key })
      expect(query?.isStale()).toBe(false)
      expect(query?.observers.every((o) => o.options.refetchInterval === false)).toBe(true)
    }
  })
})
