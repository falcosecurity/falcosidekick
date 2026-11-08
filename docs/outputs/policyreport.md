# Policy Report

Writes openreports.io `v1alpha1` reports, which Kyverno and Policy Reporter read.

- Events with a namespace (`k8s.ns.name`, else `ka.target.namespace`) go to the `Report` named `falcosidekick` in that namespace, others to the `ClusterReport` `falcosidekick`; an event whose namespace does not exist goes to `falco_namespace`.
- Each report keeps `max_events` results and drops the oldest, or with `prune_by_priority` the oldest with the lowest severity.
- Writes to one report are serialized and retried on conflict. A retried event is added once: the `uuid` property is always the event UUID, even when an output field has that name, and a result with the same `uuid` is kept as it is.
- The CRDs must be installed (`kubectl apply -f https://github.com/openreports/reports-api/releases/download/v0.2.1/install.yaml`); the service account needs `get`, `create` and `update` on `reports` and `clusterreports`.
- Startup checks the API serves both resources and the cluster report is readable. Each API request is bounded at 30s. When the API server asks to retry later (`Retry-After`), the Kubernetes client waits and retries within the same delivery attempt.

Tested with the openreports.io v0.2.1 CRDs on kind v0.30.0.

## Example

Inside the cluster no setting is needed: the output uses the pod service account.

<!-- example -->
```yaml
outputs:
  policyreport:
    kubeconfig: /etc/falcosidekick/kubeconfig
    max_events: 2000
```

<!-- BEGIN GENERATED: settings -->
<!-- Generated from the output schema by `make docs`. Do not edit. -->

## Settings

Key in the output file: `policyreport`. Category: Other. UI event source: no. Batching: no.

| Setting | Type | Default | Description |
| --- | --- | --- | --- |
| `kubeconfig` | string, file path | - | Path to a kubeconfig file; its current context is used. Empty uses the pod service account. |
| `falco_namespace` | string | - | Namespace whose `Report` receives events naming a namespace that does not exist. Empty uses the pod namespace, else `default`. |
| `max_events` | integer | `1000` | Results kept in each report, at least `1`, also set as `configuration.limits.maxResults`. Beyond it the oldest result is removed. |
| `prune_by_priority` | boolean | `false` | When a report is full, removes the oldest result of the lowest severity instead of the oldest result. |

Also takes the shared settings in [Delivery](common.md#delivery).

<!-- END GENERATED: settings -->
