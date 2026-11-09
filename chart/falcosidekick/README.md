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

With `database.backend: sqlite`, the PersistentVolumeClaim the chart created is kept (`helm.sh/resource-policy: keep`), so the stored outputs survive an uninstall; installing the same release in the same namespace reuses it. Delete it when the data is no longer needed:

```bash
kubectl --namespace falco delete pvc falcosidekick-data
```

Set `database.sqlite.persistence.keep: false` to delete the claim with the release.

## Checking the release

```bash
helm test falcosidekick --namespace falco
```

The test pod calls `/readyz` through the Service. With TLS it does not verify the server certificate.

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

`config` cannot contradict what the chart sets from the values: `database.backend`, `ui.enabled`, `database.sqlite.path` with sqlite, and `management.listen_address` with the management Service. `extraEnv` cannot set the `FALCOSIDEKICK_*` variables of the settings the chart reads: the ports, the management address, `shutdown_delay`, `tls.*`, the database backend, `connect_timeout` and paths, `ui.enabled`, `ui.event_source` and `api.secret_dirs`. Rendering fails instead.

### Secrets

Values never hold credentials: rendering fails when an output's secret field (such as `password`, `api_key` or `secret_endpoint`), the `secrets` of a header or query parameter, or `config.database.postgres.password` is set, because the chart would write it into a ConfigMap. List existing Secrets in `secrets`: each is mounted read-only at `/etc/falcosidekick/secrets/<name>` and its directory is added to `api.secret_dirs`. Outputs read them through their `_file` fields, and headers through `files`:

```yaml
outputs:
  webhook:
    host: https://receiver.example
    headers:
      Authorization:
        files: [/etc/falcosidekick/secrets/webhook/authorization]
secrets:
  - webhook
```

Output files reread their secret files on a change. The TLS Secret and the postgres password are read at startup: after rotating them, restart the pods with `kubectl --namespace falco rollout restart deploy/falcosidekick`.

### More output files

`extraOutputConfigMaps` lists existing ConfigMaps holding output files, for outputs managed apart from the release:

```yaml
extraOutputConfigMaps:
  - name: team-outputs
    key: outputs.yaml
```

Each is mounted at `/etc/falcosidekick/outputs/<name>` and passed as another `-o`, after the chart's own `outputs.yaml`, in list order; a change reloads the outputs like `outputs`. The same output name in two files merges, the later file winning for each setting. The chart does not check these files for credentials; the process refuses them with a persistent database.

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
| `sqlite` | A PersistentVolumeClaim mounted at `/var/lib/falcosidekick`. One replica only: rendering fails with `replicaCount` above 1, because the sqlite file belongs to one process, and a ReadWriteOnce volume can be mounted by pods of one node only. The Deployment uses the `Recreate` strategy, so the old pod releases the file before the new one starts. The claim is kept on uninstall and when the backend changes: see [Uninstalling the Chart](#uninstalling-the-chart). |
| `postgres` | Several replicas share the outputs. Set `host`, `database` and `user` in `config.database.postgres`, and the password Secret in `database.postgres.passwordSecret`, which the chart sets as `password_file`, or `config.database.postgres.password_file` to a file in `secrets`. |

At startup the process retries the database until `config.database.connect_timeout` (30s by default), then applies the migrations and starts the outputs before it listens. The `startupProbe` allows that time plus 30s: `probes.startup.failureThreshold` defaults to enough periods to cover it.

### TLS

Set `config.tls.enabled: true` and `tls.secretName` to a Secret holding `tls.crt` and `tls.key`, and `ca.crt` with `config.tls.mutual_tls: true`. Without `tls.secretName`, set `config.tls.cert_file` and `key_file`, and `ca_file` with mutual TLS, to files mounted otherwise, for example from `secrets`. Rendering fails when TLS is on without a certificate, when `tls.secretName` is set with TLS off, and with mutual TLS but no CA. The probes then use HTTPS; with mutual TLS they need no client certificate.

### Shutdown

`terminationGracePeriodSeconds` is `config.shutdown_delay` (5s by default) plus the 10s the process gives the server and the outputs to drain, plus 5s.

### PodDisruptionBudget

`podDisruptionBudget.enabled: true` creates one with `maxUnavailable: 1`, which lets a node drain move a single replica. `maxUnavailable: 0` blocks every voluntary eviction; `minAvailable`, when set, replaces `maxUnavailable`.

### Policy Report

`rbac.policyReport: true` creates a ClusterRole allowing `create` on openreports.io `reports` and `clusterreports`, and `get` and `update` on those named `falcosidekick`, the only ones the output writes, and binds it to the ServiceAccount. With `serviceAccount.create: false`, set `serviceAccount.name`. The ServiceAccount token is mounted when `rbac.policyReport` is true or `outputs.policyreport` is set, so RBAC managed outside the chart works too.

### Values

The following table lists the configurable parameters of the falcosidekick chart v1.0.0-beta.1 and their default values. See [values.yaml](https://github.com/falcosecurity/falcosidekick/blob/master/chart/falcosidekick/values.yaml) for the full list.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| affinity | object | `{}` | Affinity. |
| config | object | `{}` | Core configuration, written as `sidekick.yaml` with v3 keys (see docs/configuration.md). The chart sets `ui.enabled`, `ui.event_source`, `database.backend`, `database.sqlite.path`, `database.postgres.password_file`, the TLS file paths, `management.listen_address` and appends to `api.secret_dirs` as the values below require; a value here that contradicts them fails the render. Credentials are refused: use `secrets` and the `_file` keys. A change restarts the pods. |
| database.backend | string | `"inmemory"` | Where outputs created through the API and the UI layout are stored: `inmemory`, `sqlite` or `postgres`. Set the postgres connection in `config.database.postgres`. |
| database.postgres.passwordSecret.key | string | `"password"` | Key of the password in that Secret. |
| database.postgres.passwordSecret.name | string | `""` | Existing Secret holding the postgres password, mounted at `/etc/falcosidekick/postgres` and set as `database.postgres.password_file`. Read at startup: restart the pods after a rotation. |
| database.sqlite.persistence.accessModes | list | `["ReadWriteOnce"]` | Access modes of the created claim. |
| database.sqlite.persistence.annotations | object | `{}` | Annotations of the created claim. |
| database.sqlite.persistence.existingClaim | string | `""` | Existing PersistentVolumeClaim for the sqlite file. Empty creates one. |
| database.sqlite.persistence.keep | bool | `true` | Keep the created claim on uninstall and on a change of backend (`helm.sh/resource-policy: keep`). |
| database.sqlite.persistence.size | string | `"1Gi"` | Size of the created claim. |
| database.sqlite.persistence.storageClassName | string | `""` | Storage class of the created claim. Empty uses the cluster default. |
| extraEnv | list | `[]` | Extra container environment variables. The FALCOSIDEKICK_* variables of the settings the chart reads (ports, management address, shutdown_delay, tls, database backend and paths, ui, api.secret_dirs) are refused: set them in `config`. |
| extraOutputConfigMaps | list | `[]` | Existing ConfigMaps holding more output files, each `{name, key}` (`key` defaults to `outputs.yaml`). Each is mounted at `/etc/falcosidekick/outputs/<name>` and passed as another `-o` after `outputs`; a change reloads the outputs. The same output name in two files merges, the later file winning. |
| extraVolumeMounts | list | `[]` | Extra container volume mounts. |
| extraVolumes | list | `[]` | Extra pod volumes. |
| fullnameOverride | string | `""` | Overrides the full name of the resources. |
| image.digest | string | `""` | Image digest (`sha256:...`). When set, it replaces the tag and the variant. |
| image.pullPolicy | string | `"IfNotPresent"` | Image pull policy. |
| image.registry | string | `"docker.io"` | Image registry. Empty uses the repository as written. |
| image.repository | string | `"falcosecurity/falcosidekick"` | Image repository. |
| image.tag | string | `""` | Image tag. Defaults to the chart appVersion. |
| image.variant | string | `""` | Image variant: `""` (with the web UI) or `slim` (without it). `slim` requires `ui.enabled: false`. |
| imagePullSecrets | list | `[]` | Image pull secrets. |
| management.service.annotations | object | `{}` | Management Service annotations. |
| management.service.enabled | bool | `false` | Create a ClusterIP Service for the management port (API and UI) and set `management.listen_address: "::"`. The API has no authentication: restrict who can reach it. Without it, use `kubectl port-forward`. |
| management.service.ipFamilies | list | `[]` | Management Service `ipFamilies`. Empty uses the cluster default. |
| management.service.ipFamilyPolicy | string | `""` | Management Service `ipFamilyPolicy`. Empty uses the cluster default. |
| management.service.port | int | `2802` | Management Service port. |
| nameOverride | string | `""` | Overrides the chart name. |
| nodeSelector | object | `{}` | Node selector. |
| outputs | object | `{}` | Outputs, written under `outputs:` in `outputs.yaml` with v3 keys (see docs/outputs). A change reloads the outputs without a restart, once the kubelet has updated the ConfigMap. Credentials are refused: refer to them with `_file` fields pointing into `secrets`. |
| podAnnotations | object | `{}` | Pod annotations. |
| podDisruptionBudget.enabled | bool | `false` | Create a PodDisruptionBudget. |
| podDisruptionBudget.maxUnavailable | int | `1` | Maximum unavailable pods; `0` blocks every voluntary eviction. |
| podDisruptionBudget.minAvailable | string | `""` | Minimum available pods. When set, replaces `maxUnavailable`. |
| podLabels | object | `{}` | Pod labels. |
| podSecurityContext | object | `{"fsGroup":65532,"runAsGroup":65532,"runAsNonRoot":true,"runAsUser":65532,"seccompProfile":{"type":"RuntimeDefault"}}` | Pod security context. |
| priorityClassName | string | `""` | Pod priorityClassName. |
| probes.liveness.failureThreshold | int | `3` | livenessProbe failures before a restart. |
| probes.liveness.periodSeconds | int | `10` | livenessProbe period, on `/livez`. |
| probes.liveness.timeoutSeconds | int | `3` | livenessProbe timeout. |
| probes.readiness.failureThreshold | int | `3` | readinessProbe failures before the pod stops receiving traffic. |
| probes.readiness.periodSeconds | int | `5` | readinessProbe period, on `/readyz`. |
| probes.readiness.timeoutSeconds | int | `3` | readinessProbe timeout. |
| probes.startup.failureThreshold | string | `""` | startupProbe failures before a restart. Empty covers `config.database.connect_timeout` (30s by default) plus 30s: 12 periods of 5s by default. |
| probes.startup.periodSeconds | int | `5` | startupProbe period, on `/livez`. |
| probes.startup.timeoutSeconds | int | `3` | startupProbe timeout. |
| rbac.policyReport | bool | `false` | Create a ClusterRole allowing `create` on openreports.io `reports` and `clusterreports`, and `get` and `update` on those named `falcosidekick`, bound to the ServiceAccount, for the `policyreport` output. |
| replicaCount | int | `1` | Number of pods. More than 1 is refused with `database.backend: sqlite`. With the UI on, each pod's UI shows only the events that pod received. |
| resources | object | `{"requests":{"cpu":"50m","memory":"64Mi"}}` | Container resources. A pod with the UI and two outputs used under 3m CPU and 13 to 30Mi of memory; the `inmemory` output grows with its `capacity`. No limits by default. |
| secrets | list | `[]` | Names of existing Secrets. Each is mounted read-only at `/etc/falcosidekick/secrets/<name>` and its directory is added to `api.secret_dirs`. |
| securityContext | object | `{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"readOnlyRootFilesystem":true,"runAsGroup":65532,"runAsNonRoot":true,"runAsUser":65532}` | Container security context. |
| service.annotations | object | `{}` | Service annotations. |
| service.ipFamilies | list | `[]` | Service `ipFamilies`. Empty uses the cluster default. |
| service.ipFamilyPolicy | string | `""` | Service `ipFamilyPolicy`. Empty uses the cluster default. |
| service.port | int | `2801` | Service port. |
| service.type | string | `"ClusterIP"` | Service type of the ingestion port, which receives Falco events and serves `/metrics`. |
| serviceAccount.annotations | object | `{}` | ServiceAccount annotations. |
| serviceAccount.create | bool | `true` | Create a ServiceAccount. |
| serviceAccount.name | string | `""` | ServiceAccount name. Defaults to the full name when created, else `default`. Required with `rbac.policyReport` and `create: false`. |
| serviceMonitor.enabled | bool | `false` | Create a Prometheus Operator ServiceMonitor scraping `/metrics`. |
| serviceMonitor.interval | string | `""` | Scrape interval. Empty uses the Prometheus default. |
| serviceMonitor.labels | object | `{}` | Extra labels, for the Prometheus `serviceMonitorSelector`. |
| serviceMonitor.scrapeTimeout | string | `""` | Scrape timeout. Empty uses the Prometheus default. |
| serviceMonitor.tlsConfig | object | `{}` | TLS settings of the scrape, used when `config.tls.enabled` is true. |
| test.enabled | bool | `true` | Create the `helm test` pod, which calls `/readyz` through the Service. |
| test.image.pullPolicy | string | `"IfNotPresent"` | Test image pull policy. |
| test.image.registry | string | `"docker.io"` | Test image registry. |
| test.image.repository | string | `"curlimages/curl"` | Test image repository; it must provide `curl`. |
| test.image.tag | string | `"8.11.1"` | Test image tag. |
| tls.secretName | string | `""` | Existing Secret mounted at `/etc/falcosidekick/tls`, required by `config.tls.enabled: true` unless `config.tls.cert_file` and `key_file` name files mounted otherwise. Unless set in `config.tls`, `cert_file` is `tls.crt`, `key_file` is `tls.key`, and with `config.tls.mutual_tls: true` `ca_file` is `ca.crt`. Read at startup: restart the pods after a rotation. |
| tolerations | list | `[]` | Tolerations. |
| ui.enabled | bool | `true` | Serve the web UI on the management port. Sets `ui.enabled`, `ui.event_source: inmemory` and `api.allow_writes: false` unless `config.api.allow_writes` is set, and adds an `inmemory` output unless `outputs.inmemory` is set. |
