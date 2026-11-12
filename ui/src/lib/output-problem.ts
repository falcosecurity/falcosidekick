import type { OutputStatus, SavedOutput, WarningKind } from "@/lib/types"

export interface OutputProblem {
  tone: "error" | "warning"
  /** What is wrong, in a few words: the same on the canvas, the list, the detail and after a save. */
  title: string
  /** Why, as the server reports it. */
  main: string
  /** A second cause, shown only when the main one does not already say it. */
  extra?: string
}

const WARNING_TITLE: Record<Exclude<WarningKind, "destination">, string> = {
  update: "Update not applied",
  rotation: "Secret rotation not applied",
  "": "Needs a look",
}

// The start-up check reports with this prefix; the title already says it. A destination warning
// without it comes from deliveries.
const CHECK_PREFIX = "health check failed before start: "

type WarningFields = Pick<OutputStatus, "last_warning" | "warning_kind">

function isStartupCheck(status: WarningFields): boolean {
  return status.warning_kind === "destination" && status.last_warning.startsWith(CHECK_PREFIX)
}

function warningText(status: WarningFields): string {
  return isStartupCheck(status) ? status.last_warning.slice(CHECK_PREFIX.length) : status.last_warning
}

function warningTitle(status: WarningFields): string {
  if (status.warning_kind === "destination") return isStartupCheck(status) ? "Destination not verified" : "Destination failing in part"
  return WARNING_TITLE[status.warning_kind] ?? WARNING_TITLE[""]
}

type StatusFields = Pick<OutputStatus, "status" | "last_error" | "last_warning" | "warning_kind" | "circuit_state">

/**
 * The output's problem, one cause: the last delivery error, or the warning when there is no error;
 * the warning is added to an error only when it says something the error does not.
 */
export function problemOf(status: StatusFields): OutputProblem | null {
  const error = status.last_error
  const warning = warningText(status)
  if (status.status === "failed") {
    return { tone: "error", title: "Not running", main: error || warning || "The configuration did not build." }
  }
  if (error) {
    const problem: OutputProblem = { tone: "error", title: "Not delivering", main: error }
    if (warning && !warning.includes(error)) problem.extra = warning
    return problem
  }
  if (warning) return { tone: "warning", title: warningTitle(status), main: warning }
  if (status.circuit_state === "open" || status.circuit_state === "half-open") {
    return { tone: "warning", title: "Deliveries paused", main: `The circuit breaker is ${status.circuit_state} after repeated failures.` }
  }
  return null
}

/** One line for the places that show the problem in a row: "Not delivering: connection refused". */
export function problemLine(problem: OutputProblem): string {
  return `${problem.title}: ${problem.main}`
}

/** The problem of a saved output, from the status the PUT answers with; null when it is healthy or absent. */
export function saveProblemOf(saved: SavedOutput): OutputProblem | null {
  return saved.status ? problemOf(saved.status) : null
}
