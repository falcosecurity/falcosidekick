import { EmptyState } from "@/components/common/empty-state"
import { LoadingSkeleton } from "@/components/common/loading-skeleton"
import { PageHeader } from "@/components/common/page-header"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { useVersion } from "@/hooks/use-config"
import { errorMessage } from "@/lib/api-error"
import { AUTH_UNAVAILABLE_MESSAGE } from "@/lib/auth"
import { formatAbsoluteTime } from "@/lib/format"

export function SettingsPage() {
  const { data: version, isPending, isError, error } = useVersion()

  return (
    <div className="flex h-full min-h-0 flex-col">
      <PageHeader title="Settings" description="Build information." />
      <div className="mt-4 grid flex-1 content-start gap-4 overflow-auto pr-1 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle asChild className="text-base">
              <h2>Deployment</h2>
            </CardTitle>
            <CardDescription>Server build metadata reported by the backend.</CardDescription>
          </CardHeader>
          <CardContent>
            {isPending ? (
              <LoadingSkeleton lines={4} />
            ) : isError ? (
              <EmptyState title="Unable to load build information" description={errorMessage(error)} />
            ) : (
              <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-sm">
                <dt className="text-muted-foreground">Version</dt>
                <dd className="font-mono [overflow-wrap:anywhere]">{version.version}</dd>
                <dt className="text-muted-foreground">Commit</dt>
                <dd className="font-mono [overflow-wrap:anywhere]">{version.commit}</dd>
                <dt className="text-muted-foreground">Built</dt>
                <dd className="font-mono">{formatAbsoluteTime(version.build_date)}</dd>
                <dt className="text-muted-foreground">Go</dt>
                <dd className="font-mono">{version.go_version}</dd>
                <dt className="text-muted-foreground">Authentication</dt>
                <dd>{AUTH_UNAVAILABLE_MESSAGE}</dd>
              </dl>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle asChild className="text-base">
              <h2>Auto-refresh</h2>
            </CardTitle>
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
