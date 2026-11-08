import { AlertCircle, ArrowLeft, ArrowRight, Check, RefreshCw } from "lucide-react"
import { useMemo, useState, type ReactNode } from "react"
import { toast } from "sonner"

import { OutputTypeIcon } from "@/components/common/output-type-icon"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet"
import { Skeleton } from "@/components/ui/skeleton"
import { Spinner } from "@/components/ui/spinner"
import { useConfig } from "@/hooks/use-config"
import { MEDIA_LG, useMediaQuery } from "@/hooks/use-media-query"
import { useReturnFocus } from "@/hooks/use-return-focus"
import { useOutputTypes, useSaveOutput, useStoredOutput } from "@/hooks/use-output-writes"
import { usePipelineComposite } from "@/hooks/use-pipeline"
import { errorMessage, isApiError } from "@/lib/api-error"
import { cn } from "@/lib/utils"

import { ConfigureStep } from "./configure-step"
import { DriverStep } from "./driver-step"
import { buildPatch, fieldOfError, initialState, validate, type FieldValue, type FormState } from "./form-model"
import { reviewRows, ReviewStep } from "./review-step"
import { driverTitle, sectionsFor } from "./sections"

export type WizardTarget = { kind: "create" } | { kind: "edit"; name: string }

interface OutputWizardProps {
  target: WizardTarget | null
  onClose: () => void
  onSaved?: (name: string) => void
}

const STEPS = ["Driver", "Configure", "Review"] as const

function Stepper({ step, editing }: { step: number; editing: boolean }) {
  const steps = editing ? STEPS.slice(1) : STEPS
  const current = editing ? step - 1 : step
  return (
    <ol className="flex items-center gap-2 text-xs" aria-label="Steps">
      {steps.map((label, i) => (
        <li key={label} className="flex items-center gap-2" aria-current={i === current ? "step" : undefined}>
          {i > 0 && <span className="h-px w-6 bg-border" aria-hidden />}
          <span
            className={cn(
              "flex size-5 items-center justify-center rounded-full border text-[0.6875rem] font-medium tabular-nums",
              i < current && "border-brand bg-brand text-brand-foreground",
              i === current && "border-brand text-brand",
              i > current && "text-muted-foreground",
            )}
            aria-hidden
          >
            {i < current ? <Check className="size-3" /> : i + 1}
          </span>
          <span className={cn(i === current ? "font-medium text-foreground" : "text-muted-foreground")}>{label}</span>
        </li>
      ))}
    </ol>
  )
}

/** Side sheet on desktop, centered dialog below lg: the same content either way. */
function Surface({ open, onClose, title, description, stepper, children }: {
  open: boolean
  onClose: () => void
  title: string
  description: string
  stepper: ReactNode
  children: ReactNode
}) {
  const desktop = useMediaQuery(MEDIA_LG)
  const returnFocus = useReturnFocus()
  if (desktop) {
    return (
      <Sheet open={open} onOpenChange={(o) => !o && onClose()}>
        <SheetContent {...returnFocus} side="right" className="w-full gap-0 bg-popover sm:max-w-2xl xl:max-w-3xl">
          <SheetHeader className="gap-3 border-b bg-background px-6 py-4">
            <div className="flex flex-col gap-1">
              <SheetTitle>{title}</SheetTitle>
              <SheetDescription>{description}</SheetDescription>
            </div>
            {stepper}
          </SheetHeader>
          {children}
        </SheetContent>
      </Sheet>
    )
  }
  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent {...returnFocus} className="flex h-[min(90dvh,56rem)] max-w-[calc(100%-2rem)] flex-col gap-0 overflow-hidden bg-popover p-0 sm:max-w-2xl">
        <DialogHeader className="gap-3 border-b bg-background px-6 py-4 text-left">
          <div className="flex flex-col gap-1">
            <DialogTitle>{title}</DialogTitle>
            <DialogDescription>{description}</DialogDescription>
          </div>
          {stepper}
        </DialogHeader>
        {children}
      </DialogContent>
    </Dialog>
  )
}

export function OutputWizard({ target, onClose, onSaved }: OutputWizardProps) {
  const editing = target?.kind === "edit"
  const types = useOutputTypes()
  const composite = usePipelineComposite()
  const config = useConfig()
  const stored = useStoredOutput(editing ? target.name : null)
  const save = useSaveOutput()

  const [step, setStep] = useState(editing ? 1 : 0)
  const [driver, setDriver] = useState<string | null>(editing ? target.name : null)
  // edited is null until the first change; until then the form shows the initial state.
  const [edited, setEdited] = useState<FormState | null>(null)
  const [errors, setErrors] = useState<Record<string, string>>({})
  const [submitError, setSubmitError] = useState<string | null>(null)
  const [conflict, setConflict] = useState(false)
  const [openSections, setOpenSections] = useState<string[]>([])

  const type = types.data?.find((t) => t.name === driver)
  const fields = useMemo(() => type?.schema.fields ?? [], [type])
  const sections = useMemo(() => sectionsFor(fields), [fields])
  const filesOnly = config.data ? config.data.config.database.backend !== "inmemory" : true
  const configured = useMemo(() => new Set((composite.data?.outputs ?? []).map((o) => o.name)), [composite.data])

  // An edit starts from what is stored, read fresh; a new output from the empty schema.
  const initial = useMemo(() => {
    if (!type || (editing && stored.data === undefined)) return null
    return initialState(type.schema.fields, editing ? stored.data : null)
  }, [type, editing, stored.data])
  const state = edited ?? initial

  const selectDriver = (name: string) => {
    setDriver(name)
    setEdited(null)
    setErrors({})
  }

  const patch = useMemo(() => (state ? buildPatch(fields, state, editing ? stored.data : null) : {}), [fields, state, editing, stored.data])
  const rows = useMemo(() => reviewRows(fields, patch), [fields, patch])

  const setField = (name: string, value: FieldValue) => {
    if (!state) return
    setEdited({ ...state, [name]: value })
    if (errors[name]) {
      setErrors((prev) => Object.fromEntries(Object.entries(prev).filter(([key]) => key !== name)))
    }
  }

  const openFor = (fieldNames: string[]) => {
    const keys = sections.filter((s) => s.key !== "essentials" && s.fields.some((f) => fieldNames.includes(f.name))).map((s) => s.key)
    setOpenSections((prev) => [...new Set([...prev, ...keys])])
  }

  const next = () => {
    setSubmitError(null)
    if (step === 0 && driver) return setStep(1)
    if (step === 1 && state) {
      const found = validate(fields, state, { filesOnly })
      setErrors(found)
      if (Object.keys(found).length > 0) return openFor(Object.keys(found))
      setStep(2)
    }
  }

  const submit = () => {
    if (!driver) return
    setSubmitError(null)
    save.mutate(
      { name: driver, version: editing ? (stored.data?.version ?? 0) : 0, config: patch },
      {
        onSuccess: (entry) => {
          toast.success(editing ? `${driverTitle(entry.name)} updated` : `${driverTitle(entry.name)} added to the pipeline`)
          onSaved?.(entry.name)
          onClose()
        },
        onError: (error) => {
          if (isApiError(error) && error.status === 409) return setConflict(true)
          const message = errorMessage(error)
          const field = isApiError(error) && error.status === 400 ? fieldOfError(fields, message) : null
          if (field) {
            setErrors({ [field]: message.slice(message.indexOf(":") + 1).trim() || message })
            openFor([field])
            setStep(1)
            return
          }
          setSubmitError(message)
        },
      },
    )
  }

  const reload = async () => {
    setConflict(false)
    await stored.refetch()
    setEdited(null)
    setErrors({})
    setStep(1)
  }

  const title = editing ? `Edit ${driverTitle(target.name)}` : "Add output"
  const description = editing
    ? "Change the output; it is rebuilt and replaces the running one."
    : "Pick a driver, configure it, review and add it to the pipeline."

  const loading = types.isPending || config.isPending || (editing && stored.isPending)
  const loadError = types.error ?? config.error ?? stored.error

  let content: ReactNode
  if (loadError) {
    content = (
      <Alert variant="destructive">
        <AlertCircle aria-hidden />
        <AlertTitle>Unable to open the wizard</AlertTitle>
        <AlertDescription>{errorMessage(loadError)}</AlertDescription>
      </Alert>
    )
  } else if (loading) {
    content = (
      <div className="flex flex-col gap-3">
        <Skeleton className="h-9 w-full" />
        <Skeleton className="h-24 w-full" />
        <Skeleton className="h-24 w-full" />
      </div>
    )
  } else if (editing && stored.data === null) {
    content = (
      <Alert>
        <AlertCircle aria-hidden />
        <AlertTitle>This output no longer exists</AlertTitle>
        <AlertDescription>It was removed after the page loaded.</AlertDescription>
      </Alert>
    )
  } else if (step === 0) {
    content = <DriverStep types={types.data ?? []} configured={configured} selected={driver} onSelect={selectDriver} />
  } else if (step === 1 && state) {
    content = (
      <div className="flex flex-col gap-5">
        <div className="flex items-center gap-3">
          <OutputTypeIcon driver={driver!} size="sm" />
          <span className="text-sm font-medium">{driverTitle(driver!)}</span>
        </div>
        <ConfigureStep sections={sections} state={state} errors={errors} filesOnly={filesOnly} open={openSections} onOpenChange={setOpenSections} onChange={setField} />
      </div>
    )
  } else if (step === 2 && driver) {
    content = <ReviewStep driver={driver} editing={editing} rows={rows} />
  }

  const canNext = step === 0 ? driver !== null : state !== null
  return (
    <Surface open={target !== null} onClose={onClose} title={title} description={description} stepper={<Stepper step={step} editing={editing} />}>
      <div className="min-h-0 flex-1 overflow-y-auto px-6 py-5">
        {conflict && (
          <Alert className="mb-5">
            <AlertCircle aria-hidden />
            <AlertTitle>Changed by someone else</AlertTitle>
            <AlertDescription>
              <p>This output was updated after you opened it. Reload it to see the stored values, then apply your change again.</p>
              <Button type="button" size="sm" variant="outline" className="mt-2" onClick={reload}>
                <RefreshCw className="size-3.5" aria-hidden /> Reload
              </Button>
            </AlertDescription>
          </Alert>
        )}
        {submitError && (
          <Alert variant="destructive" className="mb-5">
            <AlertCircle aria-hidden />
            <AlertTitle>{editing ? "Not updated" : "Not added"}</AlertTitle>
            <AlertDescription>{submitError}</AlertDescription>
          </Alert>
        )}
        {content}
      </div>
      <div className="flex items-center justify-between gap-3 border-t bg-background px-6 py-3">
        <Button type="button" variant="ghost" onClick={step > (editing ? 1 : 0) ? () => setStep(step - 1) : onClose}>
          {step > (editing ? 1 : 0) ? (
            <>
              <ArrowLeft className="size-4" aria-hidden /> Back
            </>
          ) : (
            "Cancel"
          )}
        </Button>
        {step < 2 ? (
          <Button type="button" onClick={next} disabled={!canNext || loading}>
            Next <ArrowRight className="size-4" aria-hidden />
          </Button>
        ) : (
          <Button type="button" onClick={submit} disabled={save.isPending || conflict || (editing && rows.length === 0)}>
            {save.isPending && <Spinner />}
            {editing ? "Save changes" : "Add output"}
          </Button>
        )}
      </div>
    </Surface>
  )
}
