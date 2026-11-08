import type { HistogramBucket, Priority } from "@/lib/types"

export interface SeverityTier {
  key: string
  label: string
  priorities: readonly Priority[]
  /** CSS color of the tier's marks. */
  color: string
  /** Tailwind class for the tier's swatch. */
  swatch: string
}

// Falco's eight priorities folded into five tiers, most severe first: the four reds of emergency,
// alert and critical cannot be told apart in a stacked chart, and the reader acts on the tier.
export const SEVERITY_TIERS: readonly SeverityTier[] = [
  {
    key: "critical",
    label: "Critical+",
    priorities: ["emergency", "alert", "critical"],
    color: "var(--priority-alert)",
    swatch: "bg-priority-alert",
  },
  { key: "error", label: "Error", priorities: ["error"], color: "var(--priority-error)", swatch: "bg-priority-error" },
  {
    key: "warning",
    label: "Warning",
    priorities: ["warning"],
    color: "var(--priority-warning)",
    swatch: "bg-priority-warning",
  },
  {
    key: "notice",
    label: "Notice",
    priorities: ["notice"],
    color: "var(--priority-notice)",
    swatch: "bg-priority-notice",
  },
  {
    key: "low",
    label: "Info & debug",
    priorities: ["informational", "debug"],
    color: "var(--priority-info)",
    swatch: "bg-priority-info",
  },
]

export function tierTotals(counts: Record<string, number> | undefined): Record<string, number> {
  const totals: Record<string, number> = {}
  for (const tier of SEVERITY_TIERS) {
    totals[tier.key] = tier.priorities.reduce((sum, p) => sum + (counts?.[p] ?? 0), 0)
  }
  return totals
}

export interface TierRow extends Record<string, number> {
  t: number
}

export function tierRows(buckets: readonly HistogramBucket[]): TierRow[] {
  return buckets.map((b) => ({ t: b.t, ...tierTotals(b.by) }))
}

export const CRITICAL_PRIORITIES = SEVERITY_TIERS[0]!.priorities
