import { Activity, Database, KeyRound, Monitor, Network, RefreshCw } from "lucide-react"

import { ErrorState } from "@/components/common/error-state"
import { LoadingSkeleton } from "@/components/common/loading-skeleton"
import { PageHeader } from "@/components/common/page-header"
import {
  CodeBadge,
  CopyValue,
  NoValue,
  SettingRow,
  SettingsNav,
  SettingsSection,
  StateBadge,
  ValueList,
  type SettingsNavItem,
} from "@/components/common/settings"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent } from "@/components/ui/card"
import { useConfig, useVersion } from "@/hooks/use-config"
import { errorMessage } from "@/lib/api-error"
import { AUTH_UNAVAILABLE_MESSAGE } from "@/lib/auth"
import { formatAbsoluteTime, formatGoDuration } from "@/lib/format"
import type { CoreConfig, VersionInfo } from "@/lib/types"

const SECTIONS = {
  listeners: { id: "listeners", title: "Listeners", icon: Network },
  database: { id: "database", title: "Database", icon: Database },
  api: { id: "api", title: "API and access", icon: KeyRound },
  reload: { id: "reload", title: "Reload", icon: RefreshCw },
  observability: { id: "observability", title: "Logs and metrics", icon: Activity },
  ui: { id: "ui", title: "UI", icon: Monitor },
} satisfies Record<string, SettingsNavItem>

function address(host: string, port: number): string {
  return host ? `${host}:${port}` : `:${port}`
}

function PathOrNone({ path, none = "Not set" }: { path: string | undefined; none?: string }) {
  return path ? <CopyValue value={path} /> : <NoValue>{none}</NoValue>
}

function BuildCard({ version }: { version: VersionInfo }) {
  return (
    <Card className="gap-0 py-0 shadow-xs">
      <CardContent className="flex flex-wrap items-center gap-x-6 gap-y-2 px-5 py-3 text-sm">
        <span className="flex items-center gap-2">
          <NoValue>Version</NoValue>
          <Badge className="font-mono">{version.version}</Badge>
        </span>
        <span className="flex min-w-0 items-center gap-2">
          <NoValue>Commit</NoValue>
          <CopyValue value={version.commit} />
        </span>
        <span className="flex items-center gap-2">
          <NoValue>Built</NoValue>
          {formatAbsoluteTime(version.build_date)}
        </span>
        <span className="flex items-center gap-2">
          <NoValue>Go</NoValue>
          <code className="font-mono text-xs">{version.go_version}</code>
        </span>
      </CardContent>
    </Card>
  )
}

function ListenersSection({ cfg }: { cfg: CoreConfig }) {
  const tls = cfg.tls
  return (
    <SettingsSection {...SECTIONS.listeners} description="Where Sidekick accepts connections.">
      <SettingRow label="Ingestion" hint="Where Falco posts events, with the health, version and metrics endpoints.">
        <CopyValue value={address(cfg.listen_address, cfg.listen_port)} />
      </SettingRow>
      <SettingRow label="Ingestion TLS" hint={tls?.enabled && tls.mutual_tls ? "Clients must present a certificate signed by the client CA." : undefined}>
        <StateBadge on={tls?.enabled === true} labels={[tls?.mutual_tls ? "Mutual TLS" : "Enabled", "Disabled"]} />
      </SettingRow>
      {tls?.enabled && (
        <SettingRow label="Certificate">
          <PathOrNone path={tls.cert_file} />
        </SettingRow>
      )}
      {tls?.enabled && (
        <SettingRow label="Key">
          <PathOrNone path={tls.key_file} />
        </SettingRow>
      )}
      {tls?.enabled && tls.mutual_tls && (
        <SettingRow label="Client CA">
          <PathOrNone path={tls.ca_file} />
        </SettingRow>
      )}
      <SettingRow label="Management" hint="The API and this UI.">
        <CopyValue value={address(cfg.management.listen_address, cfg.management.listen_port)} />
      </SettingRow>
    </SettingsSection>
  )
}

function DatabaseSection({ cfg }: { cfg: CoreConfig }) {
  const db = cfg.database
  const pg = db.postgres
  return (
    <SettingsSection {...SECTIONS.database} description="Where outputs and the pipeline layout are kept.">
      <SettingRow
        label="Backend"
        hint={
          db.backend === "inmemory"
            ? "Outputs created from the UI or the API and the pipeline layout are lost on restart."
            : "Outputs and the pipeline layout are stored here; output files are provisioned into it."
        }
      >
        <CodeBadge variant="secondary">{db.backend}</CodeBadge>
      </SettingRow>
      {db.backend === "sqlite" && (
        <SettingRow label="File">
          <PathOrNone path={db.sqlite.path} />
        </SettingRow>
      )}
      {db.backend === "postgres" && [
        <SettingRow key="server" label="Server">
          <CopyValue value={address(pg.host, pg.port)} />
        </SettingRow>,
        <SettingRow key="db" label="Database and user">
          <code className="font-mono text-xs">{`${pg.database} · ${pg.user}`}</code>
        </SettingRow>,
        <SettingRow key="password" label="Password">
          {pg.password_file ? (
            <CopyValue value={pg.password_file} />
          ) : pg.password ? (
            <NoValue>
              <KeyRound className="mr-1 inline size-3.5" aria-hidden />
              Set inline, hidden
            </NoValue>
          ) : (
            <NoValue>Not set</NoValue>
          )}
        </SettingRow>,
        <SettingRow key="ssl" label="SSL mode">
          <CodeBadge>{pg.sslmode}</CodeBadge>
        </SettingRow>,
        <SettingRow key="ca" label="CA file">
          <PathOrNone path={pg.tls.ca_file} none="System CAs" />
        </SettingRow>,
        <SettingRow key="conns" label="Connections">
          up to {pg.max_connections}
        </SettingRow>,
        <SettingRow key="sync" label="Instance sync" hint="How often this instance checks for changes made by other instances.">
          every {formatGoDuration(pg.poll_interval)}
        </SettingRow>,
      ]}
      {db.backend !== "inmemory" && <SettingRow label="Connect timeout">{formatGoDuration(db.connect_timeout)}</SettingRow>}
    </SettingsSection>
  )
}

function ApiSection({ cfg }: { cfg: CoreConfig }) {
  return (
    <SettingsSection {...SECTIONS.api} description="What the API and the UI may change.">
      <SettingRow label="Writes" hint="Outputs and the layout can be changed from the UI and the API.">
        <StateBadge on={cfg.api.allow_writes} labels={["Allowed", "Read-only"]} />
      </SettingRow>
      <SettingRow label="File outputs" hint="Whether the UI and the API may change outputs defined in the output files.">
        <StateBadge on={cfg.provisioning.allow_ui_updates} labels={["Editable", "Read-only"]} />
      </SettingRow>
      <SettingRow label="Secret directories" hint="Where secret files named through the API must be.">
        <ValueList items={cfg.api.secret_dirs} empty="None" />
      </SettingRow>
      <SettingRow label="Authentication" hint={AUTH_UNAVAILABLE_MESSAGE}>
        <StateBadge on={false} labels={["Enabled", "Not available"]} />
      </SettingRow>
    </SettingsSection>
  )
}

function ReloadSection({ cfg }: { cfg: CoreConfig }) {
  return (
    <SettingsSection {...SECTIONS.reload} description="How output files and secret files are followed.">
      <SettingRow label="File change poll" hint="Catches changes the file watcher misses, such as Kubernetes volume swaps.">
        {cfg.reload.poll_interval > 0 ? `every ${formatGoDuration(cfg.reload.poll_interval)}` : <NoValue>Off</NoValue>}
      </SettingRow>
      <SettingRow label="Drain on reload" hint="Longest wait for replaced and removed outputs to deliver what they hold.">
        {formatGoDuration(cfg.reload.retire_timeout)}
      </SettingRow>
    </SettingsSection>
  )
}

function ObservabilitySection({ cfg }: { cfg: CoreConfig }) {
  return (
    <SettingsSection {...SECTIONS.observability} description="What Sidekick reports about itself.">
      <SettingRow label="Log level">
        <CodeBadge>{cfg.log_level}</CodeBadge>
      </SettingRow>
      <SettingRow label="Log format">
        <CodeBadge>{cfg.log_format}</CodeBadge>
      </SettingRow>
      <SettingRow label="Extra metric labels">
        <ValueList items={cfg.metrics.extra_labels} empty="None" />
      </SettingRow>
      <SettingRow label="Label values" hint="Distinct values kept per label before they are grouped.">
        up to {cfg.metrics.max_label_values}
      </SettingRow>
    </SettingsSection>
  )
}

function UiSection({ cfg }: { cfg: CoreConfig }) {
  return (
    <SettingsSection {...SECTIONS.ui} description="This interface and where it reads events.">
      <SettingRow label="UI">
        <StateBadge on={cfg.ui.enabled} />
      </SettingRow>
      <SettingRow label="Event source" hint="The output whose stored events the Events page and the dashboard read.">
        <CodeBadge variant="secondary">{cfg.ui.event_source}</CodeBadge>
      </SettingRow>
    </SettingsSection>
  )
}

export function ConfigurationPage() {
  const versionQuery = useVersion()
  const configQuery = useConfig()
  const failure = [versionQuery, configQuery].find((q) => q.isError)
  const version = versionQuery.data
  const cfg = configQuery.data?.config

  return (
    <div className="flex h-full min-h-0 flex-col">
      <PageHeader title="Configuration" description="The running configuration, read-only. Secrets are never shown." />
      <div className="mt-4 min-h-0 flex-1 overflow-auto pr-1 pb-6">
        {failure ? (
          <ErrorState title="Unable to load the configuration" description={errorMessage(failure.error)} />
        ) : !version || !cfg ? (
          <LoadingSkeleton lines={8} />
        ) : (
          <div className="flex flex-col gap-4">
            <BuildCard version={version} />
            <div className="grid gap-6 lg:grid-cols-[11rem_minmax(0,1fr)]">
              <SettingsNav items={Object.values(SECTIONS)} />
              <div className="flex min-w-0 flex-col gap-4">
                <ListenersSection cfg={cfg} />
                <DatabaseSection cfg={cfg} />
                <ApiSection cfg={cfg} />
                <ReloadSection cfg={cfg} />
                <ObservabilitySection cfg={cfg} />
                <UiSection cfg={cfg} />
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

export default ConfigurationPage
