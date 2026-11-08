import { Check, Copy, type LucideIcon } from "lucide-react"
import { Children, Fragment, useState, type ReactNode } from "react"
import { toast } from "sonner"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Item, ItemActions, ItemContent, ItemDescription, ItemGroup, ItemSeparator, ItemTitle } from "@/components/ui/item"
import { cn } from "@/lib/utils"

// Building blocks for read-only settings pages: a section index, sections and rows of
// label, explanation and value.

export interface SettingsNavItem {
  id: string
  title: string
  icon: LucideIcon
}

export function SettingsNav({ items }: { items: readonly SettingsNavItem[] }) {
  return (
    <nav aria-label="Sections" className="sticky top-0 hidden flex-col gap-0.5 self-start lg:flex">
      {items.map(({ id, title, icon: Icon }) => (
        <Button key={id} asChild variant="ghost" size="sm" className="justify-start font-normal text-muted-foreground hover:text-foreground">
          <a href={`#${id}`}>
            <Icon aria-hidden />
            {title}
          </a>
        </Button>
      ))}
    </nav>
  )
}

interface SettingsSectionProps extends SettingsNavItem {
  description: string
  children: ReactNode
}

/** A card of settings rows; separators go between the rows. */
export function SettingsSection({ id, title, icon: Icon, description, children }: SettingsSectionProps) {
  const rows = Children.toArray(children)
  return (
    <Card id={id} className="scroll-mt-4 gap-2 py-5 shadow-xs">
      <CardHeader className="px-5">
        <CardTitle asChild className="flex items-center gap-2 text-base">
          <h2>
            <Icon className="size-4 text-muted-foreground" aria-hidden />
            {title}
          </h2>
        </CardTitle>
        <CardDescription>{description}</CardDescription>
      </CardHeader>
      <CardContent className="px-2">
        <ItemGroup>
          {rows.map((row, i) => (
            <Fragment key={i}>
              {i > 0 && <ItemSeparator />}
              {row}
            </Fragment>
          ))}
        </ItemGroup>
      </CardContent>
    </Card>
  )
}

/** One setting: its name, what it does, its value. */
export function SettingRow({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return (
    <Item size="sm" role="group" aria-label={label} className="flex-nowrap items-start py-3">
      <ItemContent className="min-w-0">
        <ItemTitle>{label}</ItemTitle>
        {hint && <ItemDescription>{hint}</ItemDescription>}
      </ItemContent>
      <ItemActions data-value className="max-w-[60%] flex-col items-end text-right text-sm">
        {children}
      </ItemActions>
    </Item>
  )
}

/** A value in monospace with a button that copies it. */
export function CopyValue({ value }: { value: string }) {
  const [copied, setCopied] = useState(false)
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch {
      toast.error("The browser did not allow copying")
    }
  }
  return (
    <span className="inline-flex min-w-0 items-center gap-1">
      <code className="font-mono text-xs [overflow-wrap:anywhere]">{value}</code>
      <Button type="button" variant="ghost" size="icon" className="size-6 shrink-0" onClick={copy} aria-label={`Copy ${value}`}>
        {copied ? <Check aria-hidden /> : <Copy aria-hidden />}
      </Button>
    </span>
  )
}

/** An on/off state with the words the setting uses. */
export function StateBadge({ on, labels = ["Enabled", "Disabled"] }: { on: boolean; labels?: readonly [string, string] }) {
  return (
    <Badge variant="outline" className={cn("font-normal", on ? "border-status-ok/30 text-status-ok-foreground" : "text-muted-foreground")}>
      <span className={cn("size-1.5 rounded-full", on ? "bg-status-ok" : "bg-muted-foreground")} aria-hidden />
      {on ? labels[0] : labels[1]}
    </Badge>
  )
}

/** A short technical value: a backend, a mode, a level. */
export function CodeBadge({ children, variant = "outline" }: { children: ReactNode; variant?: "outline" | "secondary" }) {
  return (
    <Badge variant={variant} className="font-mono font-normal">
      {children}
    </Badge>
  )
}

/** A value that is not set, or that reads as an absence. */
export function NoValue({ children }: { children: ReactNode }) {
  return <span className="text-muted-foreground">{children}</span>
}

export function ValueList({ items, empty }: { items: readonly string[]; empty: string }) {
  if (items.length === 0) return <NoValue>{empty}</NoValue>
  return items.map((item) => <CopyValue key={item} value={item} />)
}
