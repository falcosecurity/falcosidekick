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

Core keys can be set as `FALCOSIDEKICK_<KEY>`, with dots turned into underscores: `FALCOSIDEKICK_LISTEN_PORT=2802`, `FALCOSIDEKICK_LOG_LEVEL=debug`. Outputs are configured only in files. For secrets, use the `_file` variant of a secret field (`password_file`, `api_key_file`, ...) and mount the file.

## Hot reload

Output files reload without a restart when they change: file events (including Kubernetes ConfigMap updates), `SIGHUP`, and a content poll every `reload.poll_interval` (default 30s, `0` disables). A reload that fails validation keeps the running outputs. The core file needs a restart.

## Output runtime

`runtime_defaults` in the core file applies to every output. An output can override it under its own `runtime:` key: queue size, workers, retry with exponential backoff, circuit breaker, batching (Elasticsearch, Loki, Kafka) and `minimum_priority`.

Only failures a later attempt can fix are retried: network errors, timeouts, HTTP 408, 409, 425, 429 and 5xx, and each destination's transient codes (for example AWS throttling, Kafka retriable errors, SMTP 4yz replies). A rejection such as HTTP 400, 401, 403 or 404, an untrusted certificate, a payload the destination refuses or an SMTP 5yz reply fails the event on the first attempt and does not count toward opening the circuit, since the destination answered.

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

| Route | Use |
| --- | --- |
| `POST /` | Falco events (JSON) |
| `GET /healthz` | liveness and readiness |
| `GET /metrics` | Prometheus metrics, prefix `falcosidekick_`; `metrics.extra_labels` adds output fields as labels of `falcosidekick_event_total` |
| `GET /version`, `GET /api/v1/version` | build version |
| `/api/v1/...` | events, pipeline status, output config and types, UI layout |

Routes that change outputs or the layout answer 403 unless `api.allow_writes: true`. The API has no authentication: with writes on, listen on a trusted network or on `127.0.0.1`.

## Server TLS

`tls.enabled` serves HTTPS; `tls.mutual_tls` also requires a client certificate signed by `tls.ca_file`. Client TLS towards outputs is set per output under `tls:`.
