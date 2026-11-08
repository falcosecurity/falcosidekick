import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { render, type RenderOptions, type RenderResult } from "@testing-library/react"
import type { ReactElement, ReactNode } from "react"
import { MemoryRouter } from "react-router"

import { TooltipProvider } from "@/components/ui/tooltip"

interface Options extends RenderOptions {
  initialEntries?: string[]
  queryClient?: QueryClient
}

function TestProviders({
  children,
  initialEntries = ["/"],
  queryClient,
}: {
  children: ReactNode
  initialEntries?: string[]
  queryClient: QueryClient
}) {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider delayDuration={0}>
        <MemoryRouter initialEntries={initialEntries}>{children}</MemoryRouter>
      </TooltipProvider>
    </QueryClientProvider>
  )
}

export function renderWithProviders(ui: ReactElement, options: Options = {}): RenderResult {
  const { initialEntries, queryClient, ...rest } = options
  const client =
    queryClient ??
    new QueryClient({
      defaultOptions: {
        queries: { retry: false, staleTime: 0, gcTime: 0 },
        mutations: { retry: false },
      },
    })
  return render(ui, {
    wrapper: ({ children }) => (
      <TestProviders initialEntries={initialEntries} queryClient={client}>
        {children}
      </TestProviders>
    ),
    ...rest,
  })
}

export * from "@testing-library/react"
