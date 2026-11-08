import { createElement, type ReactNode } from "react"

import { Empty, EmptyContent, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty"
import { cn } from "@/lib/utils"

interface EmptyStateProps {
  title: string
  description?: string
  icon?: ReactNode
  action?: ReactNode
  /** The heading level that fits where the state is shown. */
  headingLevel?: 2 | 3
  className?: string
}

/** Nothing to show, said plainly; errors use ErrorState. */
export function EmptyState({ title, description, icon, action, headingLevel = 3, className }: EmptyStateProps) {
  return (
    <Empty role="status" className={cn("flex-1 gap-4 p-8", className)}>
      <EmptyHeader>
        {icon && <EmptyMedia variant="icon">{icon}</EmptyMedia>}
        <EmptyTitle className="text-base font-semibold">
          {createElement(`h${headingLevel}`, null, title)}
        </EmptyTitle>
        {description && <EmptyDescription>{description}</EmptyDescription>}
      </EmptyHeader>
      {action && <EmptyContent>{action}</EmptyContent>}
    </Empty>
  )
}
