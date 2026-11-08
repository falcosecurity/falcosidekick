import { Badge } from "@/components/ui/badge"
import { classesForSource, classesForTag } from "@/lib/categorical-colors"
import { cn } from "@/lib/utils"

// Chips never grow past their container: a long value is cut and shown whole on hover.
const FIT = "inline-block max-w-full min-w-0 truncate"

export function SourceChip({ source, className }: { source: string; className?: string }) {
  return (
    <Badge variant="source" title={source} className={cn(FIT, classesForSource(source), className)}>
      {source}
    </Badge>
  )
}

export function TagChip({ tag, className }: { tag: string; className?: string }) {
  return (
    <Badge variant="tag" title={tag} className={cn(FIT, classesForTag(tag), className)}>
      {tag}
    </Badge>
  )
}
