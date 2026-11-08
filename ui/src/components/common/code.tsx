import { Check, Copy } from "lucide-react"
import { useState, type ReactNode } from "react"
import { toast } from "sonner"

import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"

/** A key, path or value named inside running text. */
export function InlineCode({ children, className }: { children: ReactNode; className?: string }) {
  return <code className={cn("rounded bg-muted px-1 py-0.5 font-mono text-xs [overflow-wrap:anywhere]", className)}>{children}</code>
}

/** A snippet to paste elsewhere, with a button that copies it. */
export function CodeBlock({ code, label }: { code: string; label: string }) {
  const [copied, setCopied] = useState(false)
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(code)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch {
      toast.error("The browser did not allow copying")
    }
  }
  return (
    <div className="relative rounded-md border bg-muted/50">
      <pre className="overflow-x-auto p-3 pr-10 font-mono text-xs leading-relaxed">
        <code>{code}</code>
      </pre>
      <Button type="button" variant="ghost" size="icon" className="absolute top-1.5 right-1.5 size-7" onClick={copy} aria-label={`Copy ${label}`}>
        {copied ? <Check aria-hidden /> : <Copy aria-hidden />}
      </Button>
    </div>
  )
}
