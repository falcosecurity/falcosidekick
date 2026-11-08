import { lazy, Suspense } from "react"
import { createBrowserRouter, RouterProvider } from "react-router"

import { LoadingSkeleton } from "@/components/common/loading-skeleton"
import { NotFoundPage } from "@/pages/not-found"

import { AppLayout } from "./layout"

const DashboardPage = lazy(() => import("@/pages/dashboard"))
const EventsPage = lazy(() => import("@/pages/events"))
const PipelinePage = lazy(() => import("@/pages/pipeline"))
const SettingsPage = lazy(() => import("@/pages/settings"))

function Lazy({ children }: { children: React.ReactNode }) {
  return <Suspense fallback={<LoadingSkeleton lines={6} />}>{children}</Suspense>
}

const router = createBrowserRouter([
  {
    element: <AppLayout />,
    children: [
      {
        index: true,
        element: (
          <Lazy>
            <DashboardPage />
          </Lazy>
        ),
      },
      {
        path: "events",
        element: (
          <Lazy>
            <EventsPage />
          </Lazy>
        ),
      },
      {
        path: "pipeline",
        element: (
          <Lazy>
            <PipelinePage />
          </Lazy>
        ),
      },
      {
        path: "settings",
        element: (
          <Lazy>
            <SettingsPage />
          </Lazy>
        ),
      },
      { path: "*", element: <NotFoundPage /> },
    ],
  },
])

export function AppRouter() {
  return <RouterProvider router={router} />
}
