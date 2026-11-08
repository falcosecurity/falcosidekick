import { Component, type ErrorInfo, type ReactNode } from "react"

import { ErrorState } from "./error-state"

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
        <ErrorState
          className="m-4"
          title="Something went wrong rendering this view"
          description={this.state.error.message}
          onRetry={this.reset}
        />
      )
    }
    return this.props.children
  }
}
