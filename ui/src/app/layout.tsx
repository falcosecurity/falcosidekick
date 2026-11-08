import { Outlet } from "react-router"

import { ErrorBoundary } from "@/components/common/error-boundary"
import { NavSidebar } from "@/components/common/nav-sidebar"
import { TopBar } from "@/components/common/top-bar"

export function AppLayout() {
  return (
    <div className="flex h-screen min-h-screen w-full bg-background text-foreground">
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-50 focus:rounded-md focus:bg-background focus:px-3 focus:py-2 focus:text-sm focus:font-medium focus:text-foreground focus:ring-2 focus:ring-ring"
      >
        Skip to main content
      </a>
      <NavSidebar />
      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar />
        <main
          id="main"
          tabIndex={-1}
          className="flex min-h-0 flex-1 flex-col overflow-hidden p-4 outline-none md:p-6"
        >
          <ErrorBoundary>
            <Outlet />
          </ErrorBoundary>
        </main>
      </div>
    </div>
  )
}
