import { useQuery } from "@tanstack/react-query"

import { PageHeader } from "@/components/common/page-header"
import { LoadingSkeleton } from "@/components/common/loading-skeleton"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { api } from "@/lib/api-client"
import { useUIStore } from "@/stores/ui-store"

export function SettingsPage() {
  const authEnabled = useUIStore((s) => s.authEnabled)

  const { data: version, isPending } = useQuery({
    queryKey: ["version"],
    queryFn: ({ signal }) => api.getVersion(signal),
  })

  return (
    <div className="flex h-full min-h-0 flex-col">
      <PageHeader title="Settings" description="Build information." />
      <div className="mt-4 grid flex-1 gap-4 overflow-auto pr-1 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Deployment</CardTitle>
            <CardDescription>Server build metadata reported by the backend.</CardDescription>
          </CardHeader>
          <CardContent>
            {isPending ? (
              <LoadingSkeleton lines={3} />
            ) : (
              <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-sm">
                <dt className="text-muted-foreground">Version</dt>
                <dd className="font-mono">{version?.version ?? "unknown"}</dd>
                <dt className="text-muted-foreground">Commit</dt>
                <dd className="font-mono">{version?.commit ?? "-"}</dd>
                <dt className="text-muted-foreground">Built</dt>
                <dd className="font-mono">{version?.date ?? "-"}</dd>
                <dt className="text-muted-foreground">Auth</dt>
                <dd>{authEnabled === false ? "disabled" : authEnabled === true ? "enabled" : "unknown"}</dd>
              </dl>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Auto-refresh</CardTitle>
            <CardDescription>
              Refresh cadence is controlled globally from the top-bar selector next to the theme
              toggle. Every page honors the same interval.
            </CardDescription>
          </CardHeader>
        </Card>
      </div>
    </div>
  )
}

export default SettingsPage
