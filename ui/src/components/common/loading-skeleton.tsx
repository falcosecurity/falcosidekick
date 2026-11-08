import { Skeleton } from "@/components/ui/skeleton"
import { cn } from "@/lib/utils"

interface LoadingSkeletonProps {
  className?: string
  lines?: number
}

export function LoadingSkeleton({ className, lines = 3 }: LoadingSkeletonProps) {
  return (
    <div
      role="status"
      aria-live="polite"
      aria-busy="true"
      className={cn("flex flex-col gap-2", className)}
    >
      {Array.from({ length: lines }, (_, i) => (
        <Skeleton key={i} className={cn("h-4 w-full", i === lines - 1 && "w-3/4")} />
      ))}
      <span className="sr-only">Loading…</span>
    </div>
  )
}

export function CardSkeleton({ className }: { className?: string }) {
  return (
    <div
      role="status"
      aria-busy="true"
      className={cn("rounded-lg border bg-card p-4", className)}
    >
      <Skeleton className="h-5 w-1/3" />
      <Skeleton className="mt-3 h-8 w-1/2" />
      <Skeleton className="mt-2 h-3 w-2/3" />
      <span className="sr-only">Loading…</span>
    </div>
  )
}

export function TableSkeleton({ rows = 6 }: { rows?: number }) {
  return (
    <div role="status" aria-busy="true" className="flex flex-col gap-2">
      {Array.from({ length: rows }, (_, i) => (
        <Skeleton key={i} className="h-9 w-full" />
      ))}
      <span className="sr-only">Loading…</span>
    </div>
  )
}
