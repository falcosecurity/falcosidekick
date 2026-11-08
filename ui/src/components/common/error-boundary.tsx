import { AlertTriangle } from "lucide-react"
import { Component, type ErrorInfo, type ReactNode } from "react"

import { Button } from "@/components/ui/button"
import { EmptyState } from "./empty-state"

interface Props {
  children: ReactNode
  fallback?: (error: Error, reset: () => void) => ReactNode
}

interface State {
  error: Error | null
}

export class ErrorBoundary extends Component<Props, State> {
  override state: State = { error: null }

  static getDerivedStateFromError(error: Error): State {
    return { error }
  }

  override componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error("ui error boundary:", error, info.componentStack)
  }

  reset = () => {
    this.setState({ error: null })
  }

  override render() {
    if (this.state.error) {
      if (this.props.fallback) {
        return this.props.fallback(this.state.error, this.reset)
      }
      return (
        <EmptyState
          icon={<AlertTriangle className="size-8" aria-hidden />}
          title="Something went wrong rendering this view"
          description={this.state.error.message}
          action={
            <Button size="sm" variant="outline" onClick={this.reset}>
              Retry
            </Button>
          }
        />
      )
    }
    return this.props.children
  }
}
