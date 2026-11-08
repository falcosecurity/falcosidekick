import { Link, useNavigate } from "react-router"

import logoIcon from "@/assets/logo-icon.svg"
import { LoginForm } from "@/components/auth/login-form"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { useUIStore } from "@/stores/ui-store"

export function LoginPage() {
  const navigate = useNavigate()
  const authEnabled = useUIStore((s) => s.authEnabled)

  return (
    <div className="flex min-h-screen items-center justify-center bg-background p-4">
      <div className="flex w-full max-w-sm flex-col gap-6">
        <div className="flex flex-col items-center gap-2">
          <img src={logoIcon} alt="" aria-hidden className="size-16" />
          <div className="text-center">
            <h1 className="text-xl font-semibold text-foreground">Falco Sidekick</h1>
            <p className="text-sm text-muted-foreground">Sign in to continue</p>
          </div>
        </div>

        <Card>
          <CardHeader className="gap-1">
            <CardTitle className="text-base">Sign in</CardTitle>
            <CardDescription>
              {authEnabled === false
                ? "No credentials are required while authentication is disabled."
                : "Sign in with the credentials configured for this deployment."}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <LoginForm
              disabled={authEnabled === false}
              onSuccess={() => navigate("/", { replace: true })}
            />
            {authEnabled === false && (
              <p className="mt-4 text-xs text-muted-foreground">
                Authentication is disabled in this deployment.{" "}
                <Link
                  to="/"
                  className="font-medium text-foreground underline underline-offset-4 hover:text-primary"
                >
                  Access the app without signing in.
                </Link>
              </p>
            )}
          </CardContent>
        </Card>

        <p className="text-center text-xs text-muted-foreground">
          Falco Sidekick v3 · part of the Falco Project
        </p>
      </div>
    </div>
  )
}

export default LoginPage
