import { useEffect } from "react"

import { AppRouter } from "@/app/routes"
import { Providers } from "@/app/providers"
import { api } from "@/lib/api-client"
import { useUIStore } from "@/stores/ui-store"

function AuthEnabledProbe() {
  const setAuthEnabled = useUIStore((s) => s.setAuthEnabled)

  useEffect(() => {
    const controller = new AbortController()
    api
      .getConfig(controller.signal)
      .then((config) => {
        const auth = extractAuthEnabled(config.config)
        setAuthEnabled(auth)
      })
      .catch(() => {
        setAuthEnabled(null)
      })
    return () => controller.abort()
  }, [setAuthEnabled])

  return null
}

function extractAuthEnabled(config: Record<string, unknown>): boolean {
  const auth = config["auth"]
  if (auth && typeof auth === "object" && "enabled" in auth) {
    return Boolean((auth as { enabled?: unknown }).enabled)
  }
  return false
}

export function App() {
  return (
    <Providers>
      <AuthEnabledProbe />
      <AppRouter />
    </Providers>
  )
}

export default App
