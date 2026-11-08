import { FileKey2, FolderLock, FolderSearch } from "lucide-react"
import { useState } from "react"

import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from "@/components/ui/command"
import { InlineCode } from "@/components/common/code"
import { InputGroup, InputGroupAddon, InputGroupButton, InputGroupInput } from "@/components/ui/input-group"
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover"
import { Spinner } from "@/components/ui/spinner"
import { useSecretFiles } from "@/hooks/use-output-writes"
import { errorMessage } from "@/lib/api-error"

interface FilePathInputProps {
  id: string
  value: string
  onChange: (path: string) => void
  invalid?: boolean
  placeholder?: string
  "aria-describedby"?: string
}

function joinPath(dir: string, name: string): string {
  return `${dir.replace(/\/+$/, "")}/${name}`
}

/** A file path typed by hand or picked from the Secrets mounted under api.secret_dirs. */
export function FilePathInput({ id, value, onChange, invalid, placeholder, ...rest }: FilePathInputProps) {
  const [open, setOpen] = useState(false)
  const secrets = useSecretFiles(open)
  const dirs = secrets.data?.dirs ?? []
  const empty = dirs.every((d) => d.keys.length === 0 && d.secrets.length === 0)

  return (
    <InputGroup>
      <InputGroupInput
        id={id}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder ?? "/etc/falcosidekick/secrets/…"}
        aria-invalid={invalid || undefined}
        className="font-mono text-xs"
        spellCheck={false}
        autoComplete="off"
        {...rest}
      />
      <InputGroupAddon align="inline-end">
        <Popover open={open} onOpenChange={setOpen}>
          <PopoverTrigger asChild>
            <InputGroupButton size="xs" aria-label="Browse secret files">
              <FolderSearch aria-hidden />
              Browse
            </InputGroupButton>
          </PopoverTrigger>
          <PopoverContent align="end" className="w-[min(28rem,calc(100vw-2rem))] p-0">
            <Command>
              <CommandInput placeholder="Search Secrets and keys…" />
              <CommandList className="max-h-72">
                {secrets.isPending ? (
                  <div className="flex items-center gap-2 p-4 text-sm text-muted-foreground">
                    <Spinner /> Reading the secret directories…
                  </div>
                ) : secrets.isError ? (
                  <div className="p-4 text-sm text-destructive">{errorMessage(secrets.error)}</div>
                ) : dirs.length === 0 ? (
                  <div className="p-4 text-sm text-muted-foreground">
                    No <InlineCode>api.secret_dirs</InlineCode> configured: type the path.
                  </div>
                ) : empty ? (
                  <div className="p-4 text-sm text-muted-foreground">The secret directories hold no files yet.</div>
                ) : (
                  <>
                    <CommandEmpty>No matching key.</CommandEmpty>
                    {dirs.map((dir) => (
                      <div key={dir.path}>
                        {dir.keys.length > 0 && (
                          <CommandGroup heading={dir.path}>
                            {dir.keys.map((key) => {
                              const path = joinPath(dir.path, key)
                              return (
                                <CommandItem key={path} value={path} onSelect={() => { onChange(path); setOpen(false) }}>
                                  <FileKey2 aria-hidden />
                                  <span className="font-mono text-xs">{key}</span>
                                </CommandItem>
                              )
                            })}
                          </CommandGroup>
                        )}
                        {dir.secrets.map((secret) => (
                          <CommandGroup key={secret.path} heading={secret.name}>
                            {secret.keys.map((key) => {
                              const path = joinPath(secret.path, key)
                              return (
                                <CommandItem key={path} value={path} onSelect={() => { onChange(path); setOpen(false) }}>
                                  <FolderLock aria-hidden />
                                  <span className="font-mono text-xs">{key}</span>
                                  <span className="ml-auto truncate text-xs text-muted-foreground">{secret.name}</span>
                                </CommandItem>
                              )
                            })}
                          </CommandGroup>
                        ))}
                      </div>
                    ))}
                    {secrets.data?.truncated && (
                      <p className="border-t p-2 text-xs text-muted-foreground">More files exist than listed: type the path.</p>
                    )}
                  </>
                )}
              </CommandList>
            </Command>
          </PopoverContent>
        </Popover>
      </InputGroupAddon>
    </InputGroup>
  )
}
