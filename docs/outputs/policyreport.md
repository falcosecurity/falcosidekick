# Policy Report

Writes openreports.io `v1alpha1` reports, which Kyverno and Policy Reporter read.

- Events with a namespace (`k8s.ns.name`, else `ka.target.namespace`) go to the `Report` named `falcosidekick` in that namespace, others to the `ClusterReport` `falcosidekick`; an event whose namespace does not exist goes to `fallback_namespace`.
- The result is `fail` from `Error` up and `warn` below: every Falco event is an alert, and `skip` means a policy was not selected. The severity still tells the priorities apart.
- Each report keeps `max_results` results (`1` to `1000`), also set as `configuration.limits.maxResults`, and drops the oldest, or with `prune_by_priority` the oldest with the lowest severity.
- Writes to one report are serialized. A conflict with another writer, such as a second replica, is retried up to 4 times after 10ms, 50ms, 250ms and 1.25s, then left to the delivery retry. A retried event is added once: the `uuid` property is always the event UUID, even when an output field has that name, and a result with the same `uuid` is kept as it is.

## Writes and report size

Every write sends the whole report, and etcd keeps each version until it compacts, so this output bounds both how often and how much it writes.

- Batching is on unless `runtime.batching.enabled` is set; `batch_size` and `flush_interval` come from `runtime_defaults` (`500` and `1s`) unless set here. Each flush reads every report it has events for once and writes it at most once. A flush that adds nothing, such as a batch sent again after a lost answer, writes nothing.
- So a report is written at most `workers` times per `flush_interval`, plus once per `batch_size` events beyond that rate, whatever the event rate. `runtime.batching.enabled: false` goes back to one read and one write per event.
- A report is also kept within 512 KiB (524288 bytes) of JSON, a third of etcd's default 1.5 MiB request limit: the oldest results, or the lowest severity ones, are removed until it fits, and the output logs once per report that the limit, not `max_results`, sets its size. A typical result takes about 1.2 KiB, so a report holds about 400 of them; events with large output fields, such as `k8saudit` ones, leave fewer.
- A result too large to fit alone in a report is refused with a permanent error, such as `policyreport result: 1 of 500 results cannot fit within the 524288-byte report limit`. Every result is checked before the first write: the oversized ones are left out, the rest of the batch is written, and only the events left out count as failed, without a retry; the output shows `degraded` with the error in `last_warning` until a clean delivery. Event truncation (`enricher.truncate_event_threshold`, see [configuration](../configuration.md)) bounds event size when such events are expected.
- Expect results in a report up to `flush_interval` after the event, and a report that holds the latest results only: it is a view of recent alerts, not an event archive.
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
    max_results: 500
    runtime:
      batching:
        flush_interval: 2s
```

<!-- BEGIN GENERATED: settings -->
<!-- Generated from the output schema by `make docs`. Do not edit. -->

## Settings

Key in the output file: `policyreport`. Category: Other. UI event source: no. Batching: yes.

| Setting | Type | Default | Description |
| --- | --- | --- | --- |
| `kubeconfig` | string, file path | - | Path to a kubeconfig file; its current context is used. Empty uses the pod service account. |
| `fallback_namespace` | string | - | Namespace whose `Report` receives events naming a namespace that does not exist. Empty uses the pod namespace, else `default`. |
| `max_results` | integer | `1000` | Results kept in each report, from `1` to `1000`, also set as `configuration.limits.maxResults`. Beyond it the oldest result is removed. A report is also kept within 512 KiB encoded, which usually holds fewer results. |
| `prune_by_priority` | boolean | `false` | When a report is full, removes the oldest result of the lowest severity instead of the oldest result. |
| `runtime.batching.enabled` | boolean | `true` | Sends events in groups, one request per group. |

Also takes the shared settings in [Delivery](common.md#delivery), [Batching](common.md#batching).

<!-- END GENERATED: settings -->
