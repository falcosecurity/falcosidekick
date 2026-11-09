# falcosidekick

[Falcosidekick](https://github.com/falcosecurity/falcosidekick) connects [Falco](https://github.com/falcosecurity/falco) to your ecosystem. It receives Falco events over HTTP and forwards them to the outputs you configure.

## Introduction

This chart installs Falcosidekick v3, in beta. Chart version 1.0.0-beta.1 deploys Falcosidekick 3.0.0-beta.1.

v3 configuration is not compatible with v2: see the [migration guide](https://github.com/falcosecurity/falcosidekick/blob/master/docs/migration.md). The chart for Falcosidekick v2 is the `0.x` line of this chart, which Helm still installs by default.

## Adding `falcosecurity` repository

```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update
```

## Installing the Chart

The v3 chart is a prerelease, so Helm installs it only with `--devel`:

```bash
helm install falcosidekick falcosecurity/falcosidekick --devel --namespace falco --create-namespace \
  --set outputs.webhook.host=http://receiver.example:8080
```

From a local checkout of the Falcosidekick repository:

```bash
helm install falcosidekick ./chart/falcosidekick --namespace falco --create-namespace \
  --set outputs.webhook.host=http://receiver.example:8080
```

Point Falco to `http://falcosidekick.falco.svc:2801/`, with `json_output: true` and `http_output.enabled: true`.

## Uninstalling the Chart

```bash
helm uninstall falcosidekick --namespace falco
```

## Configuration

`config` is written as `sidekick.yaml` and `outputs` under `outputs:` in `outputs.yaml`, with the v3 keys of the [configuration](https://github.com/falcosecurity/falcosidekick/blob/master/docs/configuration.md) and of each [output](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/README.md), without translation. A change to `config` restarts the pods; a change to `outputs` reloads the outputs without a restart, once the kubelet has updated the ConfigMap (about a minute).

```yaml
config:
  log_format: json
outputs:
  slack:
    secret_endpoint_file: /etc/falcosidekick/secrets/slack/endpoint
secrets:
  - slack
```

### Secrets

Values never hold credentials. List existing Secrets in `secrets`: each is mounted read-only at `/etc/falcosidekick/secrets/<name>` and its directory is added to `api.secret_dirs`. Outputs read them through their `_file` fields.

### Web UI

The UI is on by default and read-only: the chart sets `api.allow_writes: false` unless `config.api.allow_writes` is set, `ui.event_source: inmemory`, and adds an `inmemory` output unless `outputs.inmemory` is set. The slim image has no UI: `image.variant: slim` requires `ui.enabled: false`.

The UI and the API listen on the management port, 2802, bound to the pod loopback. Reach them with:

```bash
kubectl --namespace falco port-forward deploy/falcosidekick 2802
```

`management.service.enabled: true` creates a ClusterIP Service for that port and sets `management.listen_address: "::"`. The API has no authentication: restrict who can reach that Service. The chart creates no Ingress.

With several replicas, each pod keeps its own recent events, so each pod's UI shows only the events that pod received.

### Database

| `database.backend` | Use |
| --- | --- |
| `inmemory` | Outputs created through the API and the UI layout are lost on restart. |
| `sqlite` | A PersistentVolumeClaim mounted at `/var/lib/falcosidekick`. One replica only: rendering fails with `replicaCount` above 1, because a ReadWriteOnce volume cannot be mounted by two pods and a sqlite file written by two processes gets corrupted. The Deployment uses the `Recreate` strategy. |
| `postgres` | Several replicas share the outputs. Set the connection in `config.database.postgres`, and the password Secret in `database.postgres.passwordSecret`, which the chart sets as `password_file`. |

### TLS

Set `config.tls.enabled: true` and `tls.secretName` to a Secret holding `tls.crt` and `tls.key`, and `ca.crt` with `config.tls.mutual_tls: true`. The probes then use HTTPS; with mutual TLS they need no client certificate.

### Shutdown

`terminationGracePeriodSeconds` is `config.shutdown_delay` (5s by default) plus the 10s the process gives the server and the outputs to drain, plus 5s.

### Policy Report

`rbac.policyReport: true` creates a ClusterRole allowing `get`, `create` and `update` on openreports.io `reports` and `clusterreports`, binds it to the ServiceAccount and mounts its token, for the `policyreport` output.

### Values

The following table lists the configurable parameters of the falcosidekick chart v1.0.0-beta.1 and their default values. See [values.yaml](values.yaml) for the full list.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| affinity | object | `{}` | Affinity. |
| config | object | `{}` | Core configuration, written as `sidekick.yaml` with v3 keys (see docs/configuration.md). The chart sets `ui.*`, `database.backend`, `database.sqlite.path`, `database.postgres.password_file`, the TLS file paths, `management.listen_address` and appends to `api.secret_dirs` as the values below require. A change restarts the pods. |
| database.backend | string | `"inmemory"` | Where outputs created through the API and the UI layout are stored: `inmemory`, `sqlite` or `postgres`. Set the postgres connection in `config.database.postgres`. |
| database.postgres.passwordSecret.key | string | `"password"` | Key of the password in that Secret. |
| database.postgres.passwordSecret.name | string | `""` | Existing Secret holding the postgres password, mounted at `/etc/falcosidekick/postgres` and set as `database.postgres.password_file`. |
| database.sqlite.persistence.accessModes | list | `["ReadWriteOnce"]` | Access modes of the created claim. |
| database.sqlite.persistence.annotations | object | `{}` | Annotations of the created claim. |
| database.sqlite.persistence.existingClaim | string | `""` | Existing PersistentVolumeClaim for the sqlite file. Empty creates one. |
| database.sqlite.persistence.size | string | `"1Gi"` | Size of the created claim. |
| database.sqlite.persistence.storageClassName | string | `""` | Storage class of the created claim. Empty uses the cluster default. |
| extraEnv | list | `[]` | Extra container environment variables. |
| extraVolumeMounts | list | `[]` | Extra container volume mounts. |
| extraVolumes | list | `[]` | Extra pod volumes. |
| fullnameOverride | string | `""` | Overrides the full name of the resources. |
| image.digest | string | `""` | Image digest (`sha256:...`). When set, it replaces the tag and the variant. |
| image.pullPolicy | string | `"IfNotPresent"` | Image pull policy. |
| image.repository | string | `"falcosecurity/falcosidekick"` | Image repository. |
| image.tag | string | `""` | Image tag. Defaults to the chart appVersion. |
| image.variant | string | `""` | Image variant: `""` (with the web UI) or `slim` (without it). `slim` requires `ui.enabled: false`. |
| imagePullSecrets | list | `[]` | Image pull secrets. |
| management.service.annotations | object | `{}` | Management Service annotations. |
| management.service.enabled | bool | `false` | Create a ClusterIP Service for the management port (API and UI) and set `management.listen_address: "::"`. The API has no authentication: restrict who can reach it. Without it, use `kubectl port-forward`. |
| management.service.port | int | `2802` | Management Service port. |
| nameOverride | string | `""` | Overrides the chart name. |
| nodeSelector | object | `{}` | Node selector. |
| outputs | object | `{}` | Outputs, written under `outputs:` in `outputs.yaml` with v3 keys (see docs/outputs). A change reloads the outputs without a restart, once the kubelet has updated the ConfigMap. Refer to credentials with `_file` fields pointing into `secrets`. |
| podAnnotations | object | `{}` | Pod annotations. |
| podDisruptionBudget.enabled | bool | `false` | Create a PodDisruptionBudget. |
| podDisruptionBudget.maxUnavailable | string | `""` | Maximum unavailable pods. |
| podDisruptionBudget.minAvailable | int | `1` | Minimum available pods. Ignored when `maxUnavailable` is set. |
| podLabels | object | `{}` | Pod labels. |
| podSecurityContext | object | `{"fsGroup":65532,"runAsGroup":65532,"runAsNonRoot":true,"runAsUser":65532,"seccompProfile":{"type":"RuntimeDefault"}}` | Pod security context. |
| rbac.policyReport | bool | `false` | Create a ClusterRole allowing get, create and update on openreports.io `reports` and `clusterreports`, bound to the ServiceAccount, and mount its token, for the `policyreport` output. |
| replicaCount | int | `1` | Number of pods. More than 1 is refused with `database.backend: sqlite`. With the UI on, each pod's UI shows only the events that pod received. |
| resources | object | `{}` | Container resources. |
| secrets | list | `[]` | Names of existing Secrets. Each is mounted read-only at `/etc/falcosidekick/secrets/<name>` and its directory is added to `api.secret_dirs`. |
| securityContext | object | `{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"readOnlyRootFilesystem":true,"runAsGroup":65532,"runAsNonRoot":true,"runAsUser":65532}` | Container security context. |
| service.annotations | object | `{}` | Service annotations. |
| service.port | int | `2801` | Service port. |
| service.type | string | `"ClusterIP"` | Service type of the ingestion port, which receives Falco events and serves `/metrics`. |
| serviceAccount.annotations | object | `{}` | ServiceAccount annotations. |
| serviceAccount.create | bool | `true` | Create a ServiceAccount. |
| serviceAccount.name | string | `""` | ServiceAccount name. Defaults to the full name when created, else `default`. |
| serviceMonitor.enabled | bool | `false` | Create a Prometheus Operator ServiceMonitor scraping `/metrics`. |
| serviceMonitor.interval | string | `""` | Scrape interval. Empty uses the Prometheus default. |
| serviceMonitor.labels | object | `{}` | Extra labels, for the Prometheus `serviceMonitorSelector`. |
| serviceMonitor.scrapeTimeout | string | `""` | Scrape timeout. Empty uses the Prometheus default. |
| serviceMonitor.tlsConfig | object | `{}` | TLS settings of the scrape, used when `config.tls.enabled` is true. |
| tls.secretName | string | `""` | Existing Secret mounted at `/etc/falcosidekick/tls`, for `config.tls.enabled: true`. Unless set in `config.tls`, `cert_file` is `tls.crt`, `key_file` is `tls.key`, and with `config.tls.mutual_tls: true` `ca_file` is `ca.crt`. |
| tolerations | list | `[]` | Tolerations. |
| ui.enabled | bool | `true` | Serve the web UI on the management port. Sets `ui.enabled`, `ui.event_source: inmemory` and `api.allow_writes: false` unless `config.api.allow_writes` is set, and adds an `inmemory` output unless `outputs.inmemory` is set. |
