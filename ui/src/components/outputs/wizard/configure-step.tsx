import { CircleAlert } from "lucide-react"
import { Fragment, type ReactNode } from "react"

import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion"
import { Badge } from "@/components/ui/badge"
import { FieldDescription, FieldGroup, FieldLegend, FieldSeparator, FieldSet } from "@/components/ui/field"
import type { SchemaField } from "@/lib/types"

import { FieldControl } from "./field-control"
import { countSet, type FieldValue, type FormState } from "./form-model"
import type { FieldSection } from "./sections"

interface ConfigureStepProps {
  sections: FieldSection[]
  state: FormState
  errors: Record<string, string>
  filesOnly: boolean
  open: string[]
  onOpenChange: (open: string[]) => void
  onChange: (name: string, value: FieldValue) => void
}

function names(fields: SchemaField[]): string[] {
  return fields.map((f) => f.name)
}

function SectionStatus({ section, state, errors }: { section: FieldSection; state: FormState; errors: Record<string, string> }) {
  const set = countSet(names(section.fields), state)
  const failing = section.fields.some((f) => errors[f.name])
  return (
    <span className="ml-auto flex items-center gap-2 pr-2">
      {failing && (
        <span className="flex items-center gap-1 text-xs font-normal text-destructive">
          <CircleAlert className="size-3.5" aria-hidden />
          Needs a fix
        </span>
      )}
      {set > 0 && (
        <Badge variant="secondary" className="font-normal tabular-nums">
          {set} set
        </Badge>
      )}
    </span>
  )
}

export function ConfigureStep({ sections, state, errors, filesOnly, open, onOpenChange, onChange }: ConfigureStepProps) {
  const fieldsOf = (fields: SchemaField[]): ReactNode => (
    <FieldGroup className="gap-5">
      {fields.map((field) => (
        <FieldControl
          key={field.name}
          field={field}
          value={state[field.name]!}
          error={errors[field.name]}
          filesOnly={filesOnly}
          onChange={(value) => onChange(field.name, value)}
        />
      ))}
    </FieldGroup>
  )
  const body = (section: FieldSection): ReactNode =>
    section.groups ? (
      <div className="flex flex-col gap-5">
        {section.groups.map((group, i) => (
          <Fragment key={group.title}>
            {i > 0 && <FieldSeparator />}
            <FieldSet className="gap-4">
              <FieldLegend variant="label">{group.title}</FieldLegend>
              {fieldsOf(group.fields)}
            </FieldSet>
          </Fragment>
        ))}
      </div>
    ) : (
      fieldsOf(section.fields)
    )

  const [essentials, ...rest] = sections[0]?.key === "essentials" ? sections : [undefined, ...sections]

  return (
    <div className="flex flex-col gap-6">
      {essentials && (
        <FieldSet>
          <FieldLegend>Required</FieldLegend>
          <FieldDescription>What this output needs to start.</FieldDescription>
          {fieldsOf(essentials.fields)}
        </FieldSet>
      )}
      {rest.length > 0 && (
        <Accordion type="multiple" value={open} onValueChange={onOpenChange} className="overflow-hidden rounded-lg border bg-background">
          {rest.map((section) => (
            <AccordionItem key={section!.key} value={section!.key} className="px-4">
              <AccordionTrigger className="items-center hover:no-underline">
                <span className="flex flex-col items-start gap-0.5 text-left">
                  <span>{section!.title}</span>
                  {section!.description && <span className="text-xs font-normal text-muted-foreground">{section!.description}</span>}
                </span>
                <SectionStatus section={section!} state={state} errors={errors} />
              </AccordionTrigger>
              <AccordionContent className="pt-1 pb-5">{body(section!)}</AccordionContent>
            </AccordionItem>
          ))}
        </Accordion>
      )}
    </div>
  )
}
