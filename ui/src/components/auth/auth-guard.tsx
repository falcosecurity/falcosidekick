import type { ReactNode } from "react"
import { Navigate, useLocation } from "react-router"

import { useAuthStore } from "@/stores/auth-store"
import { useUIStore } from "@/stores/ui-store"

interface AuthGuardProps {
  children: ReactNode
}

export function AuthGuard({ children }: AuthGuardProps) {
  const authEnabled = useUIStore((s) => s.authEnabled)
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated)
  const location = useLocation()

  if (authEnabled === false || authEnabled === null) {
    return <>{children}</>
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location.pathname }} replace />
  }

  return <>{children}</>
}
