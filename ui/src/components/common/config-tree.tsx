import { Lock } from "lucide-react"

import { cn } from "@/lib/utils"

interface ConfigTreeProps {
  data: Record<string, unknown>
  secretFields?: Record<string, boolean>
  className?: string
}

export function ConfigTree({ data, secretFields, className }: ConfigTreeProps) {
  const secrets = buildSecretTree(secretFields)
  const entries = configEntries(data, secrets)
  if (entries.length === 0) {
    return <p className="text-sm text-muted-foreground">No configuration.</p>
  }
  return (
    <dl className={cn("@container/config flex flex-col gap-1 font-mono text-xs", className)}>
      {entries.map(([k, v]) => (
        <ConfigNode key={k} name={k} value={v} secrets={secrets.children.get(k)} />
      ))}
    </dl>
  )
}

interface SecretNode {
  configured?: boolean
  children: Map<string, SecretNode>
}

function buildSecretTree(fields: Record<string, boolean> = {}): SecretNode {
  const root: SecretNode = { children: new Map() }
  for (const [pointer, configured] of Object.entries(fields)) {
    if (!pointer.startsWith("/") || /~(?:[^01]|$)/.test(pointer) || typeof configured !== "boolean") continue
    const segments = pointer.slice(1).split("/").map((segment) => segment.replaceAll("~1", "/").replaceAll("~0", "~"))
    let node = root
    for (const segment of segments) {
      let child = node.children.get(segment)
      if (!child) {
        child = { children: new Map() }
        node.children.set(segment, child)
      }
      node = child
    }
    node.configured = configured
  }
  return root
}

function configEntries(value: unknown, secrets?: SecretNode): [string, unknown][] {
  const entries = new Map<string, unknown>(value != null && typeof value === "object" ? Object.entries(value) : [])
  for (const key of secrets?.children.keys() ?? []) {
    if (!entries.has(key)) entries.set(key, undefined)
  }
  return [...entries]
}

interface NodeProps {
  name: string
  value: unknown
  secrets?: SecretNode
}

function ConfigNode({ name, value, secrets }: NodeProps) {
  if (secrets?.configured !== undefined) {
    const state = secrets.configured ? "Configured" : "Not configured"
    return <Leaf
      name={name}
      label={`${name}: secret ${state.toLowerCase()}`}
      rendered={
        <span className="inline-flex max-w-full items-baseline gap-1.5 text-muted-foreground">
          <Lock className="size-3 shrink-0 self-center" aria-hidden />
          <span className="min-w-0 break-normal [overflow-wrap:anywhere]">{state}</span>
        </span>
      }
    />
  }
  const hasSecretChildren = (secrets?.children.size ?? 0) > 0
  if (value == null && !hasSecretChildren) {
    return <Leaf name={name} rendered={<span className="text-muted-foreground">null</span>} />
  }
  if (Array.isArray(value) && !hasSecretChildren) {
    if (value.length === 0) {
      return <Leaf name={name} rendered={<span className="text-muted-foreground">[]</span>} />
    }
    if (isPrimitiveArray(value)) {
      return (
        <Leaf
          name={name}
          rendered={
            <span className="break-all">
              [{value.map((v, i) => <PrimitiveSpan key={i} value={v} suffix={i < value.length - 1 ? ", " : ""} />)}]
            </span>
          }
        />
      )
    }
  }
  if (typeof value === "object" || hasSecretChildren) {
    const nestedEntries = configEntries(value, secrets)
    if (nestedEntries.length === 0) {
      return <Leaf name={name} rendered={<span className="text-muted-foreground">{"{}"}</span>} />
    }
    return (
      <Branch name={name}>
        {nestedEntries.map(([k, v]) => (
          <ConfigNode key={k} name={Array.isArray(value) ? `[${k}]` : k} value={v} secrets={secrets?.children.get(k)} />
        ))}
      </Branch>
    )
  }
  return <Leaf name={name} rendered={<PrimitiveSpan value={value} />} />
}

function Leaf({ name, rendered, label }: { name: string; rendered: React.ReactNode; label?: string }) {
  return (
    <div className="grid grid-cols-1 gap-x-3 items-baseline @[14rem]/config:grid-cols-[minmax(0,min(40%,10rem))_minmax(0,1fr)]">
      <dt className="min-w-0 text-muted-foreground [overflow-wrap:anywhere]">{name}</dt>
      <dd className="min-w-0 break-all" aria-label={label}>{rendered}</dd>
    </div>
  )
}

function Branch({ name, children }: { name: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-1">
      <div className="text-muted-foreground [overflow-wrap:anywhere]">{name}:</div>
      <div className="@container/config ml-2 flex flex-col gap-1 border-l border-border/60 pl-3">{children}</div>
    </div>
  )
}

function PrimitiveSpan({ value, suffix = "" }: { value: unknown; suffix?: string }) {
  if (typeof value === "string") {
    return <span>{value}{suffix}</span>
  }
  if (typeof value === "number" || typeof value === "bigint") {
    return <span className="text-foreground">{String(value)}{suffix}</span>
  }
  if (typeof value === "boolean") {
    return <span className="text-foreground">{value ? "true" : "false"}{suffix}</span>
  }
  return <span>{String(value)}{suffix}</span>
}

function isPrimitiveArray(arr: unknown[]): boolean {
  return arr.every((v) => v == null || typeof v === "string" || typeof v === "number" || typeof v === "boolean")
}
