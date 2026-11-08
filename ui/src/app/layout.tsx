import { Outlet } from "react-router"

import { NavSidebar } from "@/components/common/nav-sidebar"
import { TopBar } from "@/components/common/top-bar"
import { ErrorBoundary } from "@/components/common/error-boundary"

export function AppLayout() {
  return (
    <div className="flex h-screen min-h-screen w-full bg-background text-foreground">
      <NavSidebar />
      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar />
        <main className="flex min-h-0 flex-1 flex-col overflow-hidden p-4 md:p-6">
          <ErrorBoundary>
            <Outlet />
          </ErrorBoundary>
        </main>
      </div>
    </div>
  )
}
