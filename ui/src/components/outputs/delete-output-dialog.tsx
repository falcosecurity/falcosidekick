import { toast } from "sonner"

import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import { Spinner } from "@/components/ui/spinner"
import { useDeleteOutput } from "@/hooks/use-output-writes"
import { errorMessage, isApiError } from "@/lib/api-error"
import type { OutputConfigEntry } from "@/lib/types"

import { driverTitle } from "./wizard/sections"

interface DeleteOutputDialogProps {
  entry: OutputConfigEntry | null
  onClose: () => void
  onDeleted?: (name: string) => void
}

export function DeleteOutputDialog({ entry, onClose, onDeleted }: DeleteOutputDialogProps) {
  const remove = useDeleteOutput()
  const name = entry ? driverTitle(entry.name) : ""
  const confirm = (event: React.MouseEvent) => {
    event.preventDefault()
    if (!entry) return
    remove.mutate(
      { name: entry.name, version: entry.version },
      {
        onSuccess: () => {
          toast.success(`${name} removed from the pipeline`)
          onDeleted?.(entry.name)
          onClose()
        },
        onError: (error) => {
          toast.error(
            isApiError(error) && error.status === 409
              ? `${name} changed after the page loaded; open it again before removing it`
              : `${name} not removed: ${errorMessage(error)}`,
          )
          onClose()
        },
      },
    )
  }
  return (
    <AlertDialog open={entry !== null} onOpenChange={(open) => !open && !remove.isPending && onClose()}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Remove {name}?</AlertDialogTitle>
          <AlertDialogDescription>
            New events stop going to {name}; what is already queued is delivered within the drain timeout. Its
            configuration is deleted and cannot be restored
            {entry?.provisioned ? ", and it comes back at the next reload while it is in the output files" : ""}.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel disabled={remove.isPending}>Cancel</AlertDialogCancel>
          <AlertDialogAction variant="destructive" onClick={confirm} disabled={remove.isPending}>
            {remove.isPending && <Spinner />}
            Remove
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}
