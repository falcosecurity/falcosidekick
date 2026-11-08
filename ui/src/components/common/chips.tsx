import { Badge } from "@/components/ui/badge"
import { classesForSource, classesForTag } from "@/lib/categorical-colors"
import { cn } from "@/lib/utils"

export function SourceChip({ source, className }: { source: string; className?: string }) {
  return (
    <Badge variant="source" className={cn(classesForSource(source), className)}>
      {source}
    </Badge>
  )
}

export function TagChip({ tag, className }: { tag: string; className?: string }) {
  return (
    <Badge variant="tag" className={cn(classesForTag(tag), className)}>
      {tag}
    </Badge>
  )
}
