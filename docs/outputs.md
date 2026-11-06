# Outputs

Fields, defaults and comments for every output are in [`config_example_outputs.yaml`](../config_example_outputs.yaml). This page covers behavior and the tested server versions.

## Tested server versions

| Output | Versions |
| --- | --- |
| Loki | 3.7.9, 2.9.17 |
| Alertmanager | v0.34.2, v0.33.1 |
| Kafka | 4.4.0, 3.9.2 |
| Elasticsearch | 7.17.28, 8.19.23, 9.5.5 |
| OpenSearch | 2.19.7, 3.9.0 |
| AWS S3, SQS, SNS | LocalStack 4.14.0 |
| Google Cloud Pub/Sub | emulator from google-cloud-cli 592.0.0 |
| Redis | 7.4, 8 |
| OpenTelemetry Collector | contrib 0.164.0 |
| SMTP | Mailpit v1.33.0 |
| PolicyReport | openreports.io v0.2.1 CRDs on kind v0.30.0 |

Older servers may work but are not tested.

## HTTP outputs

All HTTP outputs share the target fields: `host` (scheme, host and port only), `base_path`, `endpoint` or `secret_endpoint`, `query_params`, headers, TLS and `_file` secrets. Values marked secret are never returned by the API. Only a 2xx answer counts as delivered; redirects to another origin are refused.

`HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY` apply to the HTTP outputs, the AWS outputs and OTLP `http/protobuf`, as in any Go program; requests to `localhost` and loopback addresses never use a proxy. gRPC outputs (Pub/Sub, OTLP `grpc`) follow `HTTPS_PROXY` through gRPC. Kafka, Redis, SMTP and Syslog connect directly.

## Webhook

Posts the event as JSON. `method: PUT` is accepted.

## Slack

Posts to an incoming webhook; `host` defaults to `https://hooks.slack.com` and the path goes in `secret_endpoint`.

## Loki

Pushes to `/loki/api/v1/push` under `base_path`; `tenant` sets `X-Scope-OrgID`. The health probe is `GET /ready`.

## Elasticsearch and OpenSearch

- Each event is indexed with its UUID as document id (`create`). A retried batch does not duplicate documents; an item already indexed counts as delivered.
- In a bulk request, one item rejected for good marks the whole batch as failed.
- `create_index_template: true` installs a template once, if none with that name exists. `number_of_shards` and `number_of_replicas` default to 3.
- Authentication: basic auth, `api_key` or a client certificate; combining `api_key` with basic auth, `bearer_token` or an `Authorization` header is rejected.

## Alertmanager

- Posts to every host in `hosts`. The event counts as sent when at least one host accepts it; a failing host sets the output `degraded` with `last_warning` until a delivery reaches every host.
- Label values (`alertname`, `rule`, `extra_labels`) are sent as they are; label names are sanitized.
- The health probe is `GET /-/healthy` on each host.

## Kafka

- Sync (default) waits for the broker acknowledgement. `producer.delivery_timeout` (default 10s, minimum 1s) bounds each record and the flush on shutdown.
- `producer.async: true` does not wait: an event counts as sent once buffered, and a later broker failure is counted as failed. Choose sync for exact counters.
- Idempotent writes are on only with sync and `required_acks: all`.
- A failed record is retried unless Kafka marks its error non-retriable; a batch fails for good only when every failed record does.
- Within `delivery_timeout` the client retries a record itself, for example across a leader change; with idempotent writes the broker drops those duplicates, which a pipeline retry, as a new record, cannot get.
- Client warnings and errors (connection, TLS, SASL) go to the Falcosidekick log with the broker, topic, partition and group only.

## Microsoft Teams

Posts an Adaptive Card to a Teams Workflows (Power Automate) webhook; the retired Office 365 connector `MessageCard` is not supported. `host` is required (it varies per tenant), the workflow path goes in `secret_endpoint` and the `sig` query parameter must be a secret or a file. Workflows answers 202 once the flow run is queued: a run that fails later is visible only in the flow history. Messages are capped below the 28 KB Teams limit, dropping output fields first. Not probed at startup.

## Discord

Posts embeds to a webhook; `host` defaults to `https://discord.com`, the path with the token goes in `secret_endpoint`. Startup reads the webhook with `GET`, which posts nothing: a wrong token or a deleted webhook stops startup. Embeds stay within the documented limits.

## Grafana OnCall

Posts to the formatted webhook integration (Grafana OnCall OSS, archived on 2026-03-24, and Grafana Cloud IRM use the same format). The token path goes in `secret_endpoint`; `bearer_token` sends a service account token when the integration requires one. Not probed at startup.

## PagerDuty

Sends Events API v2 `trigger` events to `/v2/enqueue` on the `us` or `eu` host (`region`). `routing_key` is a secret. The event UUID is the `dedup_key` and severity follows the Falco priority. Not probed at startup: the Events API has no read route, so any request would open an alert.

## Opsgenie

Atlassian ends Opsgenie on 2027-04-05 (sales stopped on 2025-06-04). Creates alerts with `/v2/alerts` on the `us` or `eu` host, `api_key` sent as `GenieKey`. The event UUID is the `alias`, so a retried event updates the same alert. Startup calls `GET /v2/heartbeats`: 401 or 404 stops startup; 403, the answer for an alert-only key, is accepted.

## Datadog

- Without `app_key`: Events API v1 (`/api/v1/events`), which Datadog marks deprecated and keeps for organizations that already used it.
- With `app_key`: Events API v2 on the event intake host, with `category: alert` and the event UUID as `aggregation_key`.
- `site` selects the hosts; `host` overrides both. Startup validates the API key (`/api/v1/validate`) and, with `app_key`, both keys (`/api/v2/validate_keys`).

## Falco Talon

Posts the Falco event as Falco sends it to `/` (configurable). Startup calls `GET /healthz`.

## CloudEvents

CloudEvents 1.0 over HTTP in binary mode: `ce-specversion`, `ce-id` (event UUID), `ce-source` (`source`, default `https://falco.org`), `ce-type` (`falco.rule.output.v1`), `ce-time`, plus `ce-priority`, `ce-rule`, `ce-eventsource`, `ce-hostname` and the configured `extensions` (names `[a-z0-9]+`). The body is the event JSON. Not probed at startup.

## AWS S3, SQS and SNS

- Credentials: static keys when set, otherwise the AWS SDK default chain (environment, shared files, EKS IRSA and Pod Identity, ECS and EC2 roles); `role_arn` is then assumed through STS. Instance metadata is not used to find the region.
- `endpoint` replaces the service endpoint (LocalStack, S3-compatible stores, VPC endpoints). Each call is attempted once and bounded to 30s; the pipeline retries.
- Startup stops when AWS rejects the credentials or the bucket, queue or topic does not exist. The probe reads the resource (`s3:ListBucket`, `sqs:GetQueueAttributes`, `sns:GetTopicAttributes`); without that permission the output starts degraded.
- S3 writes one object per event, `<prefix>/<YYYY-MM-DD>/<event time>_<uuid>.json`, or one NDJSON object per batch. A retry overwrites the same key.
- SQS sends batches with `SendMessageBatch`, 10 messages and 1 MiB per request; every request is sent and the batch fails when any message fails. It fails for good only when every failed entry is a sender fault. FIFO queues are not supported.
- AWS errors follow the SDK's retry rules, not the HTTP status: throttling answered with HTTP 400 is retried.
- SNS sends the output text with the event as message attributes, or the event JSON with `raw_json: true`. Attribute names SNS rejects are left out.

## Google Cloud Pub/Sub

Publishes the event JSON to `topic` in `project_id`, with `custom_attributes` as message attributes. Without `credentials` the output uses Application Default Credentials, which covers GKE Workload Identity. Startup reads the topic: a missing topic or rejected credentials stop startup; without `pubsub.topics.get` the output starts degraded. `emulator_host` targets the emulator without TLS or authentication. The `PUBSUB_EMULATOR_HOST` environment variable, when set in the process, overrides the client for every Pub/Sub output. Each publish is one request with no client-side buffering or retry, bounded at 30s; a batch is split into requests of at most 1000 messages and 10 MB, counted as encoded. Every request is sent even when an earlier one fails; a failed request fails the batch, so a retry can publish again the messages other requests delivered. A failed TLS handshake is retried, and at startup it leaves the output degraded: gRPC reports an untrusted certificate and a connection reset during the handshake the same way.

## Syslog

RFC 5424 messages over UDP, TCP or TLS; TCP and TLS use octet-counting framing (RFC 6587). `format` is `json` (the event) or `cef`. `facility` defaults to `local0`; the severity follows the Falco priority. TCP and TLS keep one connection and reconnect when the receiver closes it. Startup dials TCP and TLS receivers; an untrusted certificate stops startup.

## SMTP

One email per event, HTML or text. `tls_mode` is `starttls` (default, required), `implicit`, `opportunistic` or `none`. Credentials are sent only over TLS or to localhost. Startup connects, negotiates TLS and authenticates without sending mail: rejected credentials, a missing STARTTLS or an untrusted certificate stop startup. A 5yz reply fails the event for good, a 4yz reply is retried. With several recipients a refused recipient is retried: the client library reports only the last recipient's reply.

## Redis

Stores the event JSON with `storage_type` `list` (`RPUSH`, default), `hashmap` (`HSET`, field = event UUID) or `stream` (`XADD`, optional `max_len`). A batch goes out in one pipeline. Startup sends `PING`: rejected credentials, a missing ACL permission or an unknown database stop startup. A `WRONGTYPE`, `WRONGPASS`, `NOAUTH` or `NOPERM` reply fails the event for good; every other reply, such as `BUSY`, `LOADING` or `OOM`, is retried.

## OTLP

One output for traces, logs and metrics; each section present enables that signal, with its own `endpoint`, `protocol` (`http/protobuf` default, or `grpc`), headers, TLS, `timeout` and `compression`. `OTEL_*` environment variables have no effect.

- Traces: one span per event, kind `INTERNAL`, zero length unless `duration` is set.
- Logs: one record per event, event name `falco.alert`, severity from the priority.
- Metrics: the cumulative counter `falcosecurity.falco.rules.matches` by rule, priority, source and hostname, plus `extra_attributes`; a retried event is not counted twice.
- Resource `service.name` is `falcosidekick`. Attributes use the `falco.` prefix; output fields keep their names.
- Not probed at startup: OTLP has no request that exports nothing.
- `http/protobuf` uses the same HTTP client as the other HTTP outputs, so redirects to another origin are refused.
- Failures follow the [OTLP retry rules](https://opentelemetry.io/docs/specs/otlp/#failures): gRPC retries `CANCELLED`, `DEADLINE_EXCEEDED`, `ABORTED`, `OUT_OF_RANGE`, `UNAVAILABLE`, `DATA_LOSS`, and `RESOURCE_EXHAUSTED` when the collector sends `RetryInfo`; HTTP retries 429, 502, 503 and 504. A partial success is not retried. When one signal fails, a retry exports every enabled signal again; the event fails for good only when every failed signal does.

## PolicyReport

Writes openreports.io `v1alpha1` reports, which Kyverno and Policy Reporter read. Events with a namespace (`k8s.ns.name`, else `ka.target.namespace`) go to the `Report` named `falcosidekick` in that namespace, others to the `ClusterReport` `falcosidekick`; an event whose namespace does not exist goes to `falco_namespace`. Each report keeps `max_events` results (default 1000) and drops the oldest, or with `prune_by_priority` the oldest with the lowest severity. Writes to one report are serialized and retried on conflict. The CRDs must be installed (`kubectl apply -f https://github.com/openreports/reports-api/releases/download/v0.2.1/install.yaml`); the service account needs `get`, `create` and `update` on `reports` and `clusterreports`. Startup checks the API serves both resources and the cluster report is readable. Each API request is bounded at 30s. When the API server asks to retry later (`Retry-After`), the Kubernetes client waits and retries within the same delivery attempt.
