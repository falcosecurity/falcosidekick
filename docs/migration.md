# Migrate from v2

v2 configuration does not load in v3: unknown keys are rejected. Rewrite it with these differences in mind. v2 stays maintained on the [`2.x`](https://github.com/falcosecurity/falcosidekick/tree/2.x) branch for security and critical fixes.

## What changed

| Area | v2 | v3 |
| --- | --- | --- |
| Files | one `config.yaml` | core file (`-c`) and output files (`-o`, repeatable) |
| Key style | `listenport`, `webhookurl` | `listen_port`, `secret_endpoint` |
| Output setup | file or environment variables | output files only; secrets through `_file` fields |
| Enabling an output | non-empty address | presence of its block under `outputs:` |
| Outputs | many, see the `2.x` README | Webhook, Slack, Loki, Elasticsearch, Alertmanager, Kafka |
| Reload | restart | output files reload on change, `SIGHUP` or poll |
| Delivery | - | per-output queue, retry, circuit breaker, optional batching |
| Image tags | `latest`, `2.*` | `v3-*`, `v3-latest`, `-slim` variants |
| Port | 2801 | 2801 |

Falco needs no change: it posts to `/` as before.

## Addresses

v3 splits every address into public and secret parts, so tokens in a URL never appear in the API or logs.

| Output | v2 | v3 |
| --- | --- | --- |
| Webhook | `address: https://collector.example:8443/gateway/events?team=security&token=TOKEN` | `host: https://collector.example:8443`, `endpoint: /gateway/events`, `query_params: {team: {values: [security]}, token: {secrets: [TOKEN]}}` |
| Slack | `webhookurl: https://hooks.slack.com/services/T000/B000/XXXX` | `secret_endpoint: /services/T000/B000/XXXX` |
| Slack via proxy | `webhookurl: https://slack-proxy.example/hooks/XXXX` | `host: https://slack-proxy.example`, `secret_endpoint: /hooks/XXXX` |
| Loki | `hostport: https://loki.example/tenant-a`, `endpoint: /loki/api/v1/push` | `host: https://loki.example`, `base_path: /tenant-a`, `endpoint: /loki/api/v1/push` |
| Elasticsearch | `hostport: https://proxy.example/es` | `host: https://proxy.example`, `base_path: /es` |
| Alertmanager | `hostport: [https://am-1.example/alertmanager, https://am-2.example/alertmanager]` | `hosts: [https://am-1.example, https://am-2.example]`, `base_path: /alertmanager` |

## Metrics

| v2 | v3 |
| --- | --- |
| `falcosecurity_falcosidekick_inputs_total` | `falcosidekick_input_total{source,status}` |
| `falcosecurity_falcosidekick_outputs_total{destination,status}` | `falcosidekick_output_total{output,status}` |
| `falcosecurity_falcosidekick_falco_events_total{hostname,rule,priority,priority_raw,source,k8s_ns_name,k8s_pod_name,...}` | `falcosidekick_event_total{rule,priority,source,...}` |
| `prometheus.extralabels: "k8s.ns.name,proc.name"` | `metrics.extra_labels: [k8s.ns.name, proc.name]` in the core file |

v2 also added hostname, Kubernetes namespace and pod, custom fields and templated fields as event labels by default. v3 adds only the output fields listed in `metrics.extra_labels`: list `k8s.ns.name` and `k8s.pod.name` there to keep those series. The hostname label and `priority_raw` are not available in v3. Dashboards built on v2 names need updating.

## Behavior to check

- Startup now fails when a destination rejects credentials, answers 404 on its probe or presents an untrusted certificate. v2 started anyway.
- Alertmanager label values, including `alertname` and `rule`, are sent unchanged, as in v2.
- Elasticsearch documents use the event UUID as id.
- The management API and the UI are new. Writes through the API are off unless `api.allow_writes: true`.
