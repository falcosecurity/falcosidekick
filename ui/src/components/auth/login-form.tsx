import { zodResolver } from "@hookform/resolvers/zod"
import { Loader2 } from "lucide-react"
import { useForm } from "react-hook-form"
import { z } from "zod"

import { Button } from "@/components/ui/button"
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form"
import { Input } from "@/components/ui/input"
import { useAuthStore } from "@/stores/auth-store"

const loginSchema = z.object({
  username: z.string().min(1, "Username is required"),
  password: z.string().min(1, "Password is required"),
})

type LoginFormValues = z.infer<typeof loginSchema>

interface LoginFormProps {
  disabled?: boolean
  onSuccess?: () => void
}

export function LoginForm({ disabled = false, onSuccess }: LoginFormProps) {
  const login = useAuthStore((s) => s.login)
  const lastError = useAuthStore((s) => s.lastError)
  const clearError = useAuthStore((s) => s.clearError)

  const form = useForm<LoginFormValues>({
    resolver: zodResolver(loginSchema),
    defaultValues: { username: "", password: "" },
  })

  async function onSubmit(values: LoginFormValues) {
    if (disabled) return

    clearError()
    try {
      await login(values.username, values.password)
      onSuccess?.()
    } catch {
      form.setValue("password", "")
    }
  }

  const isSubmitting = form.formState.isSubmitting
  const isDisabled = disabled || isSubmitting

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(onSubmit)} className="flex flex-col gap-4" noValidate>
        <FormField
          control={form.control}
          name="username"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Username</FormLabel>
              <FormControl>
                <Input
                  autoComplete="username"
                  autoFocus={!disabled}
                  disabled={isDisabled}
                  {...field}
                />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
        <FormField
          control={form.control}
          name="password"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Password</FormLabel>
              <FormControl>
                <Input
                  type="password"
                  autoComplete="current-password"
                  disabled={isDisabled}
                  {...field}
                />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />

        {!disabled && lastError && (
          <div
            role="alert"
            className="rounded-md border border-status-error/30 bg-status-error/10 px-3 py-2 text-sm text-status-error-foreground"
          >
            {lastError}
          </div>
        )}

        <Button type="submit" className="w-full" disabled={isDisabled}>
          {isSubmitting && <Loader2 className="mr-2 size-4 animate-spin" aria-hidden />}
          {disabled ? "Sign in unavailable" : "Sign in"}
        </Button>
      </form>
    </Form>
  )
}
