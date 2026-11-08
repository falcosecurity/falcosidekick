import { AlertTriangle, RefreshCw } from "lucide-react"

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"

interface ErrorStateProps {
  title: string
  /** The backend's message, shown as it came. */
  description?: string
  onRetry?: () => void
  className?: string
}

/** Something could not be loaded: what, why, and a way to try again. */
export function ErrorState({ title, description, onRetry, className }: ErrorStateProps) {
  return (
    <Alert variant="destructive" className={cn("self-start", className)}>
      <AlertTriangle aria-hidden />
      <AlertTitle>{title}</AlertTitle>
      {(description || onRetry) && (
        <AlertDescription>
          {description && <p className="[overflow-wrap:anywhere]">{description}</p>}
          {onRetry && (
            <Button type="button" size="sm" variant="outline" className="mt-2" onClick={onRetry}>
              <RefreshCw aria-hidden /> Retry
            </Button>
          )}
        </AlertDescription>
      )}
    </Alert>
  )
}
