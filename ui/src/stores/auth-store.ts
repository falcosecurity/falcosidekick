import { create } from "zustand"
import { createJSONStorage, persist } from "zustand/middleware"

import { api, setAccessToken, setUnauthorizedHandler } from "@/lib/api-client"

interface AuthState {
  accessToken: string | null
  refreshToken: string | null
  expiresAt: string | null
  username: string | null
  isAuthenticated: boolean
  lastError: string | null
  login: (username: string, password: string) => Promise<void>
  logout: () => void
  clearError: () => void
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
      accessToken: null,
      refreshToken: null,
      expiresAt: null,
      username: null,
      isAuthenticated: false,
      lastError: null,

      async login(username: string, password: string) {
        set({ lastError: null })
        try {
          const response = await api.login(username, password)
          set({
            accessToken: response.access_token,
            refreshToken: response.refresh_token,
            expiresAt: response.expires_at,
            username,
            isAuthenticated: true,
            lastError: null,
          })
          setAccessToken(response.access_token)
        } catch (err) {
          const detail = extractError(err)
          set({
            accessToken: null,
            refreshToken: null,
            expiresAt: null,
            username: null,
            isAuthenticated: false,
            lastError: detail,
          })
          setAccessToken(null)
          throw err
        }
      },

      logout() {
        set({
          accessToken: null,
          refreshToken: null,
          expiresAt: null,
          username: null,
          isAuthenticated: false,
          lastError: null,
        })
        setAccessToken(null)
      },

      clearError() {
        if (get().lastError !== null) set({ lastError: null })
      },
    }),
    {
      name: "falcosidekick-auth",
      storage: createJSONStorage(() => sessionStorage),
      partialize: (state) => ({
        accessToken: state.accessToken,
        refreshToken: state.refreshToken,
        expiresAt: state.expiresAt,
        username: state.username,
        isAuthenticated: state.isAuthenticated,
      }),
      onRehydrateStorage: () => (state) => {
        if (state?.accessToken) {
          setAccessToken(state.accessToken)
        }
      },
    },
  ),
)

setUnauthorizedHandler(() => {
  useAuthStore.getState().logout()
})

function extractError(err: unknown): string {
  if (err && typeof err === "object" && "response" in err) {
    const response = (err as { response?: { status?: number; data?: { error?: string; detail?: string } } }).response
    if (response?.status === 503) {
      return "Authentication is not available in this deployment."
    }
    if (response?.status === 401) {
      return "Invalid username or password."
    }
    if (response?.status === 429) {
      return "Too many attempts. Try again shortly."
    }
    if (response?.data?.detail) return response.data.detail
    if (response?.data?.error) return response.data.error
  }
  if (err instanceof Error) return err.message
  return "Unable to reach the server."
}
