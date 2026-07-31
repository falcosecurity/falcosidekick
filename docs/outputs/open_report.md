# OpenReport

- **Category**: Other
- **Website**: https://github.com/openreports/reports-api

The OpenReport output writes Falco events to the OpenReports `openreports.io/v1alpha1` API. Events associated with a Kubernetes namespace are stored in a `Report` named `falco-report`; events without a namespace are stored in the cluster-scoped `ClusterReport` named `falco-cluster-report`.

## Configuration

| Setting | Environment variable | Default | Description |
| --- | --- | --- | --- |
| `openreport.enabled` | `OPENREPORT_ENABLED` | `false` | Enable the OpenReport output. |
| `openreport.kubeconfig` | `OPENREPORT_KUBECONFIG` | `""` | Kubeconfig file to use when Falcosidekick runs outside the cluster. |
| `openreport.falconamespace` | `OPENREPORT_FALCONAMESPACE` | `""` | Fallback namespace when an event refers to a namespace that does not exist. When empty, Falcosidekick uses its service-account namespace or `default`. |
| `openreport.maxevents` | `OPENREPORT_MAXEVENTS` | `1000` | Maximum results retained in each report. Must be greater than zero; the newest results are retained in FIFO order. |
| `openreport.minimumpriority` | `OPENREPORT_MINIMUMPRIORITY` | `""` (`debug`) | Minimum event priority for this output: `emergency`, `alert`, `critical`, `error`, `warning`, `notice`, `informational`, `debug`, or `""`. |

Environment variables override values from the YAML configuration file.

```yaml
openreport:
  enabled: false
  kubeconfig: "~/.kube/config"
  falconamespace: ""
  maxevents: 1000
  minimumpriority: ""
```

The output accepts events from the `syscall`, `syscalls`, and `k8saudit` sources. It can be enabled alongside the deprecated Policy Report output; each output writes and counts its own resource type independently.

## Install the OpenReports API

The OpenReports custom resource definitions are required before enabling this output. Falcosidekick uses the API and generated client from OpenReports v0.2.1:

```shell
kubectl apply -f https://github.com/openreports/reports-api/releases/download/v0.2.1/install.yaml
```

See the [OpenReports installation documentation](https://github.com/openreports/reports-api#installing) for other installation methods.

## RBAC

The Falcosidekick identity needs these permissions to create and update reports:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: falcosidekick-openreport
rules:
  - apiGroups: ["openreports.io"]
    resources: ["reports", "clusterreports"]
    verbs: ["get", "create", "update"]
```

Optional `get` access to core `namespaces` lets Falcosidekick detect a missing event namespace and use `openreport.falconamespace`. Report writes still proceed in the event namespace when namespace reads are not authorized.

> [!IMPORTANT]
> The current Falcosidekick Helm chart exposes only the deprecated `policyreport` settings and `wgpolicyk8s.io` RBAC. Until chart support for `openreport` is added, supply the OpenReport configuration and RBAC separately.
