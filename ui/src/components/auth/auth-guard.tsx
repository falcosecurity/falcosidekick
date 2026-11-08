import type { ReactNode } from "react"
import { Navigate, useLocation } from "react-router"

import { AUTH_AVAILABLE } from "@/lib/auth"
import { useAuthStore } from "@/stores/auth-store"

interface AuthGuardProps {
  children: ReactNode
}

export function AuthGuard({ children }: AuthGuardProps) {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated)
  const location = useLocation()

  if (!AUTH_AVAILABLE || isAuthenticated) {
    return <>{children}</>
  }

  return <Navigate to="/login" state={{ from: location.pathname }} replace />
}
