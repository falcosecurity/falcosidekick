/**
 * Categorical color helpers for tags and sources.
 *
 * Returns a stable Tailwind class set per-key by hashing the key into a fixed
 * palette. Semantic mappings (MITRE, filesystem, network, k8s, etc.) are
 * honored first; everything else falls through to the hash palette.
 */

const PALETTE: readonly string[] = [
  "border-category-1/30 bg-category-1/15 text-category-1-foreground",
  "border-category-2/30 bg-category-2/15 text-category-2-foreground",
  "border-category-3/30 bg-category-3/15 text-category-3-foreground",
  "border-category-4/30 bg-category-4/15 text-category-4-foreground",
  "border-category-5/30 bg-category-5/15 text-category-5-foreground",
  "border-category-6/30 bg-category-6/15 text-category-6-foreground",
  "border-category-7/30 bg-category-7/15 text-category-7-foreground",
  "border-category-8/30 bg-category-8/15 text-category-8-foreground",
  "border-category-9/30 bg-category-9/15 text-category-9-foreground",
  "border-category-10/30 bg-category-10/15 text-category-10-foreground",
] as const

function hashIndex(s: string): number {
  let h = 0
  for (let i = 0; i < s.length; i++) {
    h = (h << 5) - h + s.charCodeAt(i)
    h |= 0
  }
  return Math.abs(h) % PALETTE.length
}

function take(i: number): string {
  return PALETTE[i % PALETTE.length] as string
}

const TAG_CATEGORIES: Array<{ match: (t: string) => boolean; index: number }> = [
  { match: (t) => t.startsWith("mitre_"), index: 1 },
  { match: (t) => t === "network" || t === "tcp" || t === "udp", index: 0 },
  { match: (t) => t === "filesystem" || t === "file" || t === "fs", index: 3 },
  { match: (t) => t === "process" || t === "proc", index: 8 },
  { match: (t) => t === "container" || t === "cri", index: 5 },
  { match: (t) => t === "k8s" || t === "kubernetes", index: 6 },
  { match: (t) => t === "shell", index: 4 },
  { match: (t) => t === "users" || t === "user", index: 2 },
  { match: (t) => t === "database" || t === "db", index: 9 },
  { match: (t) => t === "logs" || t === "logging" || t === "audit", index: 7 },
  { match: (t) => t === "drift", index: 4 },
  { match: (t) => t === "software_mgmt" || t === "package", index: 9 },
]

export function classesForTag(tag: string): string {
  const lower = tag.toLowerCase()
  for (const cat of TAG_CATEGORIES) {
    if (cat.match(lower)) return take(cat.index)
  }
  return take(hashIndex(lower))
}

const SOURCE_OVERRIDES: Record<string, number> = {
  syscall: 0,
  k8s_audit: 6,
  kubernetes: 6,
  docker: 5,
  cri: 5,
  plugin: 2,
}

export function classesForSource(source: string): string {
  const lower = source.toLowerCase()
  const override = Object.hasOwn(SOURCE_OVERRIDES, lower) ? SOURCE_OVERRIDES[lower] : undefined
  if (override != null) return take(override)
  return take(hashIndex(lower))
}

export function rankedColor(index: number): string {
  return take(index)
}
