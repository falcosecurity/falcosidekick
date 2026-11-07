# Configuration

## Files and flags

```sh
falcosidekick -c sidekick.yaml -o outputs.yaml [-o more-outputs.yaml]
falcosidekick --version
```

- `-c`: core file. Without it, defaults and environment variables apply.
- `-o`: output file, repeatable. Files merge left to right; the same output name deep-merges.

Unknown keys are rejected at startup, in both files.

## Environment

Every core key can be set as `FALCOSIDEKICK_<KEY>`, with dots turned into underscores, also keys without a default: `FALCOSIDEKICK_LISTEN_PORT=2802`, `FALCOSIDEKICK_TLS_ENABLED=true`. Lists are comma-separated. Outputs are configured only in files. For secrets, use the `_file` variant of a secret field (`password_file`, `api_key_file`, ...) and mount the file.

Every file an output reads (`_file` secrets, header and query `files`, TLS certificates and keys) must be a regular file of at most 1 MiB; symlinks to one, as in Kubernetes secret volumes, are fine. An output file that writes `name:` with nothing after it is rejected: write `name: {}` to use the defaults.

## Hot reload

Output files reload without a restart when they change: file events (including Kubernetes ConfigMap updates), `SIGHUP`, and a content poll every `reload.poll_interval` (default 30s, `0` disables). A reload that fails validation keeps the running outputs. The core file needs a restart.

A reload builds every new or changed output first, then switches them all at once, so new events go to the new outputs. The replaced and removed outputs then deliver what they already queued, together, for at most `reload.retire_timeout` (default 10s); what they still hold after it is counted as dropped. Counters, `last_success` and `last_error` carry over to the replacement. Shutdown also waits for outputs still finishing after a reload.

## Output runtime

`runtime_defaults` in the core file applies to every output. An output can override it under its own `runtime:` key: queue size, workers, retry with exponential backoff, circuit breaker, batching (Elasticsearch, Loki, Kafka) and `minimum_priority`.

A failure fails the event on the first attempt only when the destination's protocol says a retry cannot succeed; it then does not count toward opening the circuit, since the destination answered. Examples: HTTP 400, 401, 403 or 404 from an HTTP output, an untrusted certificate, a payload the destination refuses, an SMTP 5yz reply, a Kafka error marked non-retriable, a Redis `WRONGTYPE`, `WRONGPASS`, `NOAUTH` or `NOPERM` reply. Every other failure is retried within `retry.max_attempts`: network errors, timeouts, HTTP 408, 409, 425, 429 and 5xx, throttling such as AWS answering 400 with a throttling code, and any reply the output does not recognize. Outputs with their own protocol rules (AWS, Kafka, OTLP, Pub/Sub, Redis, SMTP) are described in [outputs](outputs.md). In a batch or a fan-out, the event fails for good only when every failed part does.

After `circuit_breaker.failure_threshold` consecutive failures the circuit opens: workers stop taking events and the queue waits, so a destination outage does not turn queued events into failures. Each worker keeps the event, or with batching the batch, it already holds. New events beyond `queue_size` are dropped. After `reset_timeout` one probe goes through; `success_threshold` successes close the circuit and the queue resumes. Events still waiting when the output is reloaded or stopped are counted as dropped.

## Destination health check

At startup, on reload and on an API change, each output probes its destination for at most 5s:

- rejected credentials (401, 403), a wrong path (404), an untrusted TLS certificate or a Kafka SASL failure: startup stops, or the reload or API change is rejected and the previous output keeps running;
- any other failure (connection refused, timeout, 5xx): the output starts as `degraded` and reports the reason in `last_warning` until it delivers.

Elasticsearch treats 403 as transient, because its probe (`GET /`) needs the `monitor` privilege. Webhook and Slack are not probed: their endpoint accepts only POST.

Outputs are probed concurrently. `runtime.health_check: false` skips the probe for one output, or for all of them under `runtime_defaults`, for example when a proxy rejects the probe route but accepts deliveries.

## Output status

`GET /api/v1/pipeline/status` returns, per output: counters (`sent_total`, `failed_total`, `dropped_total`), queue depth, circuit state, `last_error`, `last_warning` and `status`:

| Status | Meaning |
| --- | --- |
| `idle` | nothing delivered yet |
| `ok` | delivering |
| `degraded` | delivering with a problem: circuit open or half-open, a destination not reachable before start, or an Alertmanager host failing while another accepts |
| `error` | the last delivery failed (`last_error`) |

## HTTP endpoints

Two listeners keep event ingestion apart from the API, which has no authentication:

- ingestion, `listen_address:listen_port` (default `0.0.0.0:2801`): `POST /`, `/healthz`, `/version`, `/metrics`;
- management, `management.listen_address:management.listen_port` (default `127.0.0.1:2802`): `/api/v1/...`, the UI and `/healthz`. An empty address is refused; write `0.0.0.0` to listen on every interface.

`tls` applies to both. Expose the management listener only to trusted clients.

| Route | Use |
| --- | --- |
| `POST /` | Falco events (JSON) |
| `GET /healthz` | liveness and readiness, on both listeners |
| `GET /metrics` | Prometheus metrics, prefix `falcosidekick_`; `metrics.extra_labels` adds output fields as labels of `falcosidekick_event_total`. Labels taken from events (rule, source, extra labels) keep at most `metrics.max_label_values` distinct values each (default 1000); later values are recorded as `other` and counted in `falcosidekick_metric_label_overflow_total{label}`. `falcosidekick_output_total` and `falcosidekick_output_drop_total` count events, a batch included |
| `GET /version` | build version, ingestion listener |
| `/api/v1/...` | management listener: events, pipeline status, output config and types, UI layout, `/api/v1/version` |

Routes that change outputs or the layout answer 403 unless `api.allow_writes: true`. With writes on, keep `management.listen_address` on `127.0.0.1` or a trusted network.

`PUT /api/v1/pipeline/outputs/<name>` takes `{"version": N, "config": {...}}` and nothing else. `version` is the one `GET` returned, or 0 to create the output; if the output changed in the meantime the answer is 409, so read it again and retry. `DELETE /api/v1/pipeline/outputs/<name>?version=N` follows the same rule. A file reload changes the version only of the outputs whose settings changed. Keys left out of `config` keep their stored value; a secret sent as `<name>_file` replaces the stored value, and the other way round. The database stores the `_file` path, never the content read from it; the file is read each time the output is built, so a rotated secret takes effect at the next reload, write or restart. `GET` shows the path and reports the secret as set in `secret_fields`.

A file path sent through the API (a `_file` secret, header and query `files`, TLS files, `kubeconfig`) is accepted only if it resolves, after symlinks, to a regular file of at most 1 MiB inside one of the absolute directories in `api.secret_dirs`. The default, an empty list, refuses every such path. Paths already in the output file are kept as they are. The check matters because the output sends what it reads to a destination the same request chooses.

Both listeners close a connection that takes more than 30s to send a request or to read the answer, or stays idle for 2 minutes.

## Server TLS

`tls.enabled` serves HTTPS; `tls.mutual_tls` also requires a client certificate signed by `tls.ca_file`. Client TLS towards outputs is set per output under `tls:`.
