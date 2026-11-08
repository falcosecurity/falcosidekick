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

A reload builds every new or changed output first, stores the output files in the database, then switches them all at once, so new events go to the new outputs. If the database refuses the change nothing is switched, and the next reload tries again. The replaced and removed outputs then deliver what they already queued, together, for at most `reload.retire_timeout` (default 10s); what they still hold after it is counted as dropped. Counters, `last_success` and `last_error` carry over to the replacement. Shutdown also waits for outputs still finishing after a reload.

## Output runtime

`runtime_defaults` in the core file applies to every output. An output can override it under its own `runtime:` key: queue size, workers, retry with exponential backoff, circuit breaker, batching (Elasticsearch, Loki, Kafka) and `minimum_priority`.

A failure fails the event on the first attempt only when the destination's protocol says a retry cannot succeed; it then does not count toward opening the circuit, since the destination answered. Examples: HTTP 400, 401, 403 or 404 from an HTTP output, an untrusted certificate, a payload the destination refuses, an SMTP 5yz reply, a Kafka error marked non-retriable, a Redis `WRONGTYPE`, `WRONGPASS`, `NOAUTH` or `NOPERM` reply. Every other failure is retried within `retry.max_attempts`: network errors, timeouts, HTTP 408, 409, 425, 429 and 5xx, throttling such as AWS answering 400 with a throttling code, and any reply the output does not recognize. Outputs with their own protocol rules (AWS, Kafka, OTLP, Pub/Sub, Redis, SMTP) are described on their [output pages](outputs/README.md). In a batch or a fan-out, the event fails for good only when every failed part does.

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
| `failed` | not running: an output created through the API did not build at startup (`last_error`); its stored settings are kept, and a `PUT` or `DELETE` clears the state |

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
| `/api/v1/...` | management listener: events (list filters repeat their parameter once per value, each taken as written: `?rule=A&rule=B`, so a rule name may contain a comma), pipeline status, output config and types, UI layout, `/api/v1/version`, `/api/v1/config` (the core configuration this instance runs with and its `runtime_defaults`, read from its files; the database never stores it), `/api/v1/secrets` (the names of the files under `api.secret_dirs`, never their contents) |

Routes that change outputs or the layout, and `GET /api/v1/secrets`, answer 403 unless `api.allow_writes: true`. With writes on, keep `management.listen_address` on `127.0.0.1` or a trusted network.

`PUT /api/v1/pipeline/outputs/<name>` takes `{"version": N, "config": {...}}` and nothing else. `version` is the one `GET` returned, or 0 to create the output; if the output changed in the meantime the answer is 409, so read it again and retry. `DELETE /api/v1/pipeline/outputs/<name>?version=N` follows the same rule. The database accepts or refuses the change before the running output is replaced or removed: when it is unreachable the answer is 503 `{"error":"database unavailable"}` and nothing changes; the database error is only logged. Each API request has 30s to complete, building an output and its database calls included. During shutdown the API stops first; a change in progress completes, or is canceled once the shutdown deadline passes. A file reload changes the version only of the outputs whose settings changed. Keys left out of `config` keep their stored value; a secret sent as `<name>_file` replaces the stored value, and the other way round. The database stores the `_file` path, never the content read from it; the file is read each time the output is built. A reload (file change, poll or `SIGHUP`, which works without output files too) rereads the secret files of these outputs and rebuilds those whose value changed, without a new version; an unreadable file keeps the running output as it was. `GET` shows the path and reports the secret as set in `secret_fields`.

With `database.backend: sqlite` or `postgres`, no secret value is stored: a secret written inline, in an output file or through the API, is refused (startup stops, the reload or the request fails) with `<field>: secrets cannot be stored; use <field>_file`, or `use files` for header and query secrets. Write the path of a file that holds it instead. `inmemory` accepts inline values. With writes on and `api.secret_dirs` empty, startup warns that outputs with secrets cannot be created through the API.

A file path sent through the API (a `_file` secret, header and query `files`, TLS files, `kubeconfig`) is accepted only if it resolves, after symlinks, to a regular file of at most 1 MiB inside one of the absolute directories in `api.secret_dirs`. The default, an empty list, refuses every such path. Paths already in the output file are kept as they are. The check matters because the output sends what it reads to a destination the same request chooses. Changes are watched in each directory of `api.secret_dirs` and in the directories directly below it, such as `<secret_dir>/<name>/<key>` for a mounted Kubernetes Secret; a file deeper than that is not watched, so send `SIGHUP` after changing it. The files an output file names (`_file` secrets, header and query `files`, TLS files) are watched where they are, at any depth, and also checked every `reload.poll_interval`.

Both listeners close a connection that takes more than 30s to send a request or to read the answer, or stays idle for 2 minutes.

## Database

`database.backend` selects where outputs and the UI layout are stored:

| Backend | Use |
| --- | --- |
| `inmemory` (default) | nothing survives a restart; outputs from the output files are loaded again at start |
| `sqlite` | one instance; `database.sqlite.path` is a file on a local filesystem, created with mode 0600 (its `-wal` and `-shm` files take the same mode). Back it up with `sqlite3 <path> .backup <copy>`, or copy the file while Sidekick is stopped |
| `postgres` | several instances can share one database |

Postgres settings: `host`, `port` (5432), `database`, `user`, `password` or `password_file`, `sslmode` (`verify-full` by default; `disable`, `require`, `verify-ca`), `tls.ca_file` (system CAs when empty), `max_connections` (4), `poll_interval` (10s). Postgres 17 and 18 are tested. Sidekick creates and upgrades its tables (all named `falcosidekick_*`) at start; a database upgraded by a newer Sidekick is refused. `database.connect_timeout` (30s) bounds opening it; an unreachable database stops startup.

With postgres, every instance applies the outputs another instance creates, changes or deletes through the API: it is notified at once, and checks the stored outputs every `poll_interval` in case a notification was lost (a lost listener connection reconnects and checks too). A change an instance cannot build, for example because a secret file is missing there, leaves its previous output running with status `degraded` and `last_warning` naming the version it could not apply; it is tried again at each check. Each check is counted in `falcosidekick_reload_total{source="replica"}`, a change not applied in `falcosidekick_reload_failures_total{source="replica"}`. A write whose commit the database did not confirm answers 503 with "the change may have been applied": read the output again.

Outputs from the output files are written to the database at each start and reload; instances sharing a database should run the same output files, otherwise each start or reload of one replaces the outputs of the others, as happens briefly during a rolling update.

## Server TLS

`tls.enabled` serves HTTPS; `tls.mutual_tls` also requires a client certificate signed by `tls.ca_file`. Client TLS towards outputs is set per output under `tls:`.
