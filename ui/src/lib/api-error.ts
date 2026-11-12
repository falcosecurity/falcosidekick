/** A refused value, located by its configuration path ("runtime.workers", `headers["X"].files[0]`). */
export interface FieldProblem {
  path: string
  message: string
}

/** Where a write was refused: the configuration itself, building the output or the database. */
export type ErrorPhase = "validate" | "build" | "store"

export class ApiError extends Error {
  readonly status: number
  readonly phase?: ErrorPhase
  /** Absent for errors that name no field. */
  readonly fields?: FieldProblem[]

  constructor(status: number, message: string, details: { phase?: ErrorPhase; fields?: FieldProblem[] } = {}) {
    super(message)
    this.name = "ApiError"
    this.status = status
    this.phase = details.phase
    this.fields = details.fields
  }
}

export function isApiError(error: unknown): error is ApiError {
  return error instanceof ApiError
}

export function errorMessage(error: unknown, fallback = "Unknown error"): string {
  if (error instanceof Error && error.message) return error.message
  return fallback
}

const PHASES: readonly string[] = ["validate", "build", "store"]

/** Reads the optional phase and fields of an error body, dropping entries of the wrong shape. */
export function errorDetails(body: unknown): { phase?: ErrorPhase; fields?: FieldProblem[] } {
  if (!body || typeof body !== "object") return {}
  const { phase, fields } = body as { phase?: unknown; fields?: unknown }
  const details: { phase?: ErrorPhase; fields?: FieldProblem[] } = {}
  if (typeof phase === "string" && PHASES.includes(phase)) details.phase = phase as ErrorPhase
  if (Array.isArray(fields)) {
    details.fields = fields.filter(
      (f): f is FieldProblem => !!f && typeof f === "object" && typeof f.path === "string" && typeof f.message === "string",
    )
  }
  return details
}
