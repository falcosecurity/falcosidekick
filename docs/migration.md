# Migrate from v2

v2 configuration does not load in v3: unknown keys are rejected. Rewrite it with these differences in mind. v2 stays maintained on the [`2.x`](https://github.com/falcosecurity/falcosidekick/tree/2.x) branch for security and critical fixes.

## What changed

| Area | v2 | v3 |
| --- | --- | --- |
| Files | one `config.yaml` | core file (`-c`) and output files (`-o`, repeatable) |
| Key style | `listenport`, `webhookurl` | `listen_port`, `secret_endpoint` |
| Output setup | file or environment variables | output files only; secrets through `_file` fields |
| Enabling an output | non-empty address | presence of its block under `outputs:` |
| Outputs | many, see the `2.x` README | see [outputs](outputs.md) |
| Reload | restart | output files reload on change, `SIGHUP` or poll |
| Delivery | - | per-output queue, retry, circuit breaker, optional batching |
| Image tags | `latest`, `2.*` | `v3-*`, `v3-latest`, `-slim` variants |
| Port | 2801 | 2801 for events, health, version and metrics; 2802 on `127.0.0.1` for the API and the UI |

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
| Teams | `webhookurl:` an Office 365 connector URL | create a Workflows webhook; `host`, `secret_endpoint` (workflow path), `query_params.sig.secrets` |
| Discord | `webhookurl: https://discord.com/api/webhooks/ID/TOKEN` | `secret_endpoint: /api/webhooks/ID/TOKEN` |
| Grafana OnCall | `webhookurl: https://oncall.example/integrations/v1/formatted_webhook/TOKEN/` | `host: https://oncall.example`, `secret_endpoint: /integrations/v1/formatted_webhook/TOKEN/` |
| Talon | `address: http://falco-talon:2803` | `host: http://falco-talon:2803` |
| CloudEvents | `address: http://broker/path` | `host: http://broker`, `endpoint: /path` |
| PagerDuty | `routingkey`, `region` | `routing_key` (secret), `region` |
| Opsgenie | `apikey`, `region` | `api_key` (secret), `region` |
| Datadog | `apikey`, `host` | `api_key` (secret), `site` or `host`; optional `app_key` for Events API v2 |
| AWS | `aws.accesskeyid`, `aws.secretaccesskey`, `aws.region`, `aws.rolearn`, `aws.externalid` | the same fields on each output, snake_case: `access_key_id`, `secret_access_key`, `region`, `role_arn`, `external_id` |
| S3 | `aws.s3.bucket`, `aws.s3.prefix`, `aws.s3.objectcannedacl` | `awss3.bucket`, `prefix`, `object_canned_acl` |
| SQS | `aws.sqs.url` | `awssqs.queue_url` |
| SNS | `aws.sns.topicarn`, `aws.sns.rawjson` | `awssns.topic_arn`, `raw_json` |
| Pub/Sub | `gcp.credentials`, `gcp.pubsub.projectid`, `gcp.pubsub.topic`, `gcp.pubsub.customattributes` | `gcppubsub.credentials` (secret, raw or base64 JSON), `project_id`, `topic`, `custom_attributes` |
| Syslog | `syslog.host`, `port`, `protocol`, `format` | `host`, `port`, `protocol` (`tcp`, `udp`, `tls`), `format`, `facility` |
| SMTP | `smtp.hostport`, `tls`, `authmechanism`, `to: "a@x,b@x"` | `host`, `port`, `tls_mode`, `auth_mechanism`, `to: [a@x, b@x]` |
| Redis | `redis.address`, `storagetype` | `address`, `storage_type` |
| OTLP | `otlp.traces.endpoint`, `extraenvvars` | `otlp.traces.endpoint`, `protocol`, `timeout`, `compression`; the same for `logs` and `metrics` |
| PolicyReport | `falconamespace`, `maxevents`, `prunebypriority` | `falco_namespace`, `max_events`, `prune_by_priority` |

`customheaders` becomes `headers` with `values`, `secrets` or `files`; `checkcert: false` becomes `tls.insecure_skip_verify: true`; `minimumpriority` becomes `runtime.minimum_priority`.

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
- Delivery retries only failures that a later attempt can fix; a rejected event (for example HTTP 400 or 401) fails at once. See [configuration](configuration.md).
- Alertmanager label values, including `alertname` and `rule`, are sent unchanged, as in v2.
- Elasticsearch documents use the event UUID as id.
- Teams sends Adaptive Cards to Workflows webhooks; the retired MessageCard format is gone. `output_format: facts` is now `fields`.
- PagerDuty: severity follows the Falco priority (v2 always sent `critical`), `source` is the hostname, the event details are sent (v2 built them but dropped them), and `region: eu` now reaches the EU host (v2 always used the US host).
- Opsgenie: the event UUID is the alert `alias`, so a retried event updates the same alert; Falco tags become Opsgenie tags.
- Datadog: the API key travels in the `DD-API-KEY` header instead of the URL.
- Discord: the embed color is an integer and payloads are trimmed to Discord limits.
- CloudEvents: any non-2xx answer counts as failed.
- AWS: `accesskeyid`, `rolearn` and `externalid` now take effect, and `session_token` is new. S3 keys use the event time in UTC plus the UUID (v2 used the local receive time). SNS leaves out attribute names AWS rejects instead of failing the publish. `checkidentity` is replaced by the startup probe.
- Pub/Sub: a missing topic stops startup; `workloadidentity` is gone, Application Default Credentials cover it.
- Syslog: messages follow RFC 5424 with octet counting on TCP (v2 sent RFC 3164 lines). v2 sent facility 0 (`kern`), reserved for the kernel; v3 defaults to `local0`. Set `facility` when receivers filter on the old value.
- SMTP: STARTTLS is required by default; credentials are never sent in clear text to a remote server. `auth_mechanism` accepts `plain`, `xoauth2` and `none`; `oauthbearer`, `external` and `anonymous` are not available (use `xoauth2` for OAuth 2.0 tokens, `none` instead of `anonymous`).
- OTLP: resource `service.name` is `falcosidekick` (v2: `falco`); attributes are `falco.rule`, `falco.priority`, `falco.source` and so on; spans are `INTERNAL` and zero length by default (v2: `SERVER`, 1s). The metric keeps its Prometheus name, `falcosecurity_falco_rules_matches_total`, with `falco_*` labels. `http/json` is not supported.
- PolicyReport: reports use openreports.io `Report` and `ClusterReport`, named `falcosidekick` (v2: `wgpolicyk8s.io` `PolicyReport`, `falco-policy-report`). `policy` is the Falco rule and `category` the event source. `prune_by_priority` now works. Install the openreports CRDs; RBAC on namespaces is no longer needed.
- The management API and the UI are new. Writes through the API are off unless `api.allow_writes: true`; file paths in API writes need `api.secret_dirs`.
