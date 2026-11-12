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

Every core key can be set as `FALCOSIDEKICK_<KEY>`, with dots turned into underscores, also keys without a default: `FALCOSIDEKICK_LISTEN_PORT=3801`, `FALCOSIDEKICK_TLS_ENABLED=true`. Lists are comma-separated. Outputs are configured only in files. For secrets, use the `_file` variant of a secret field (`password_file`, `api_key_file`, ...) and mount the file.

Every value is read as the type of its setting, from the core file, the environment, the output files, the API and the stored outputs alike: a boolean is `true` or `false` (also as text, as the environment gives it), a number is a number or its text and never a boolean, a duration is written with its unit (`30s`, `1m`; `0` alone where the docs allow it), a list is a list. A value of another type is refused on its field, with the same message everywhere.

Every file an output reads (`_file` secrets, header and query `files`, TLS certificates and keys) must be a regular file of at most 1 MiB; symlinks to one, as in Kubernetes secret volumes, are fine. An output file that writes `name:` with nothing after it is rejected: write `name: {}` to use the defaults.

## Hot reload

Output files reload without a restart when they change: file events (including Kubernetes ConfigMap updates), `SIGHUP`, and a content poll every `reload.poll_interval` (default 30s, `0` disables). A reload that fails validation keeps the running outputs. The core file needs a restart.

A reload builds every new or changed output first, stores the output files in the database, then switches them all at once, so new events go to the new outputs. If the database is unavailable nothing is switched and the change stays pending: it is tried again after 5s, then after a delay that doubles up to 30s, each within ±10%, also with `reload.poll_interval: 0`, until it applies. An invalid output file is reported once, as one failed reload, and is tried again only when the input changes or on `SIGHUP`. A change seen by both the file events and the poll is attempted, and counted in `falcosidekick_reloads_total`, once. The replaced and removed outputs then deliver what they already queued, together, for at most `reload.retire_timeout` (default 10s); what they still hold after it is counted as dropped. Counters, `last_success` and `last_error` carry over to the replacement. Shutdown also waits for outputs still finishing after a reload.

## Output runtime

`runtime_defaults` in the core file applies to every output. An output can override it under its own `runtime:` key: queue size, workers, retry with exponential backoff, circuit breaker, batching (Elasticsearch, Loki, Kafka) and `minimum_priority`.

A failure fails the event on the first attempt only when the destination's protocol says a retry cannot succeed; it then does not count toward opening the circuit, since the destination answered. Examples: HTTP 400, 401, 403 or 404 from an HTTP output, an untrusted certificate, a payload the destination refuses, an SMTP 5yz reply, a Kafka error marked non-retriable, a Redis `WRONGTYPE`, `WRONGPASS`, `NOAUTH` or `NOPERM` reply. Every other failure is retried within `retry.max_attempts`: network errors, timeouts, HTTP 408, 409, 425, 429 and 5xx, throttling such as AWS answering 400 with a throttling code, and any reply the output does not recognize. Outputs with their own protocol rules (AWS, Kafka, OTLP, Pub/Sub, Redis, SMTP) are described on their [output pages](outputs/README.md). In a batch or a fan-out, the event fails for good only when every failed part does. A failed batch counts all its events as failed, unless the error names its failed events: then the others count as sent, the events the destination rejected for good count as failed at once, and only the retryable ones are sent again, with the same backoff and circuit rules; the output shows `degraded` with the error in `last_warning` (`warning_kind: destination`) until a clean delivery. PolicyReport (results too large for a report) and Elasticsearch (bulk items) report their events this way; SQS, Pub/Sub, Kafka and Redis still retry or fail the whole batch.

After `circuit_breaker.failure_threshold` consecutive failures the circuit opens: workers stop taking events and the queue waits, so a destination outage does not turn queued events into failures. Each worker keeps the event, or with batching the batch, it already holds. New events beyond `queue_size` are dropped. After `reset_timeout` one probe goes through; `success_threshold` successes close the circuit and the queue resumes. Events still waiting when the output is reloaded or stopped are counted as dropped.

These settings are checked at startup, on reload and on an API change, before anything is allocated; a value outside its range is refused:

| Setting | Range |
| --- | --- |
| `workers` | 1-256 |
| `queue_size` | 1-100,000 |
| `batching.batch_size` | 1-10,000 |
| `workers` × `batching.batch_size` | at most 100,000 with batching on |
| `batching.flush_interval` | 10ms-1h |
| `retry.max_attempts` | 1-100 |
| `retry.multiplier` | 1-10 |
| `retry.initial_interval`, `retry.max_interval` | 1ms-1h |
| `circuit_breaker.failure_threshold`, `success_threshold` | 1-10,000 |
| `circuit_breaker.reset_timeout` | 1s-1h |
| `inmemory` output `capacity` | 1-100,000 |
| `metrics.max_label_values` | 1-10,000 |
| `database.postgres.max_connections` | 1-1,000 |

## Destination health check

At startup, on reload and on an API change, each output probes its destination for at most 5s. The same rule applies everywhere, to output files, reloads, API changes and outputs restored from the database:

- a configuration that is invalid in itself (a malformed or out-of-range value, a missing or unreadable local file, a certificate or key file that does not load, an unsupported combination) is refused: startup stops before serving, a reload is rejected and the running outputs stay, an API change answers 400 and nothing is saved, a stored output starts `failed`;
- a valid configuration whose destination fails the probe is applied: unreachable, DNS failure, a missing topic, bucket, queue or CRD, rejected credentials (401, 403), a wrong path (404), an untrusted TLS certificate, a Kafka SASL failure, a timeout or a 5xx. The output starts `degraded` with the reason in `last_warning` (`warning_kind: destination`), the other outputs deliver, and the output delivers by itself once the destination accepts, without a restart. An API change answers 200 with the output status.

An untrusted certificate still refuses the connection: the output never falls back to plain text or skips verification. Delivery to a destination that rejects the configuration fails each event without retry until it accepts.

Elasticsearch treats 403 as transient, because its probe (`GET /`) needs the `monitor` privilege. Webhook and Slack are not probed: their endpoint accepts only POST.

Outputs are probed concurrently. `runtime.health_check: false` skips the probe for one output, or for all of them under `runtime_defaults`, for example when a proxy rejects the probe route but accepts deliveries.

## Output status

`GET /api/v1/pipeline/status` returns, per output: counters (`sent_total`, `failed_total`, `dropped_total`), queue depth, circuit state, `last_error`, `last_warning`, `warning_kind` and `status`. `warning_kind` says what `last_warning` is about, and is empty without a warning: `destination` (the destination failed its probe before start, rejected part of a batch, or an Alertmanager host fails while another accepts), `update` (a stored change was not applied here; the output runs as before) or `rotation` (a renewed secret file was not applied; the output keeps its previous secret).

| Status | Meaning |
| --- | --- |
| `idle` | nothing delivered yet |
| `ok` | delivering |
| `degraded` | delivering with a problem: circuit open or half-open, a destination that failed its probe before start or rejected part of a batch, an Alertmanager host failing while another accepts, or a change not applied (`last_warning`) |
| `error` | the last delivery failed (`last_error`) |
| `failed` | not running: an output created through the API did not build at startup (`last_error`); its stored settings are kept, and a `PUT` or `DELETE` clears the state |

## HTTP endpoints

Two listeners keep event ingestion apart from the API, which has no authentication:

- ingestion, `listen_address:listen_port` (default `:2801`, every interface, IPv4 and IPv6): `POST /`, `/livez`, `/readyz`, `/metrics`;
- management, `management.listen_address:management.listen_port` (default `127.0.0.1:2802`): `/api/v1/...` and the UI. An empty address is refused; write `::` to listen on every interface.

`tls` applies to both. With `tls.mutual_tls`, the management listener requires a client certificate in the handshake; ingestion requires one on every route except `/livez`, `/readyz` and `/metrics`, since kubelet probes and most scrapers present none. Expose the management listener only to trusted clients.

| Route | Use |
| --- | --- |
| `POST /` | Falco events (JSON), the format of Falco's `http_output` |
| `GET /livez` | liveness: 200 while the process serves |
| `GET /readyz` | readiness: 200 once the pipeline runs; 503 from SIGTERM on, while events are still accepted for `shutdown_delay` (default `5s`), so Kubernetes stops routing to the pod before the listener closes |
| `GET /metrics` | Prometheus metrics; see [Metrics](#metrics) |
| `/api/v1/...` | management listener: events (list filters repeat their parameter once per value, each taken as written: `?rule=A&rule=B`, so a rule name may contain a comma), pipeline status, output config and types, UI layout, `/api/v1/version`, `/api/v1/config` (the core configuration this instance runs with and its `runtime_defaults`, read from its files; the database never stores it; durations are written as Go duration strings such as `30s` or `1m30s`), `/api/v1/secrets` (the names of the files under `api.secret_dirs`, never their contents) |

Routes that change outputs or the layout, and `GET /api/v1/secrets`, answer 403 unless `api.allow_writes: true`. With writes on, keep `management.listen_address` on `127.0.0.1` or a trusted network.

`PUT /api/v1/pipeline/outputs/<name>` takes `{"version": N, "config": {...}}` and nothing else. `version` is the one `GET` returned, or 0 to create the output; if the output changed in the meantime the answer is 409, so read it again and retry. `DELETE /api/v1/pipeline/outputs/<name>?version=N` follows the same rule. The database accepts or refuses the change before the running output is replaced or removed: when it is unreachable the answer is 503 `{"error":"database unavailable","phase":"store"}` and nothing changes; the database error is only logged. Each API request has 30s to complete, building an output and its database calls included. During shutdown the API stops first; a change in progress completes, or is canceled once the shutdown deadline passes. A file reload changes the version only of the outputs whose settings changed. Keys left out of `config` keep their stored value; a secret sent as `<name>_file` replaces the stored value, and the other way round. The database stores the `_file` path, never the content read from it; the file is read each time the output is built. A reload (file change, poll or `SIGHUP`, which works without output files too) rereads the secret files of these outputs and rebuilds those whose value changed, without a new version; an unreadable file keeps the running output with its previous secret, records the reload as `failure` (`partial` when other changes were applied with it), and shows the output `degraded` with the reason in `last_warning`. The warning clears once the file reads again as the running value or the output is rebuilt with the new one. `GET` shows the path and reports the secret as set in `secret_fields`.

With `database.backend: sqlite` or `postgres`, no secret value is stored: a secret written inline, in an output file or through the API, is refused (startup stops, the reload or the request fails) with `<field>: secrets cannot be stored; use <field>_file`, or `use files` for header and query secrets. Write the path of a file that holds it instead. `inmemory` accepts inline values. With writes on and `api.secret_dirs` empty, startup warns that outputs with secrets cannot be created through the API.

A file path sent through the API (a `_file` secret, header and query `files`, TLS files, `kubeconfig`) is accepted only if it resolves, after symlinks, to a regular file of at most 1 MiB inside one of the absolute directories in `api.secret_dirs`. The default, an empty list, refuses every such path. Paths already in the output file are kept as they are. The check matters because the output sends what it reads to a destination the same request chooses. Changes are watched in each directory of `api.secret_dirs` and in the directories directly below it, such as `<secret_dir>/<name>/<key>` for a mounted Kubernetes Secret; a file deeper than that is not watched, so send `SIGHUP` after changing it. The files an output file names (`_file` secrets, header and query `files`, TLS files) are watched where they are, at any depth, and also checked every `reload.poll_interval`.

Both listeners close a connection that takes more than 30s to send a request or to read the answer, or stays idle for 2 minutes. A request body is at most 4 MiB; a larger one is answered 413 before it is read, and on `POST /` it counts in `falcosidekick_ingest_requests_total{status="invalid"}`.

### API errors

Every error answer is JSON with `error`, a summary that never quotes a submitted value. A refused output change (`PUT` and `DELETE` on `/api/v1/pipeline/outputs/<name>`) also has `phase` and, when the refusal names settings, `fields`:

```json
{"error": "apply output: ...: runtime.workers: must be an integer between 1 and 256",
 "phase": "validate",
 "fields": [{"path": "runtime.workers", "message": "must be an integer between 1 and 256"}]}
```

- `phase` is `validate` (the request, a value, a file path or the runtime settings; 400), `build` (the output did not build from local state, such as a TLS file that does not load; 400) or `store` (a version conflict, 409, or the database, 503). A destination that fails its probe never refuses a change.
- `fields[].path` is the setting as the output's configuration names it, such as `runtime.workers`, `tls.ca_file`, `logs.tls.ca_file`, `password_file` or `headers["X-Token"]`; `message` is the reason, such as `must be an integer`, `must be a duration such as 30s or 1m` or `is required`. A refusal about the whole configuration has no field entry.
- A saved change answers 200 with the stored output and `status`, the status of the output now running: `"status": "degraded"` with `last_warning` and `warning_kind: destination` when its destination failed the probe.
- A panic or an unexpected error answers 500 `{"error": "internal error; see the falcosidekick log"}`; the cause is only logged.

## Events

Sidekick reads the JSON of Falco's `http_output` (`json_output: true`).

- `priority` is read in any casing, and Falco's short `Info` too. The event JSON that outputs forward and the API serves writes it as Falco does: `Warning`.
- `output_fields` may be missing, as with Falco's `json_include_output_fields_property: false`.
- A missing `hostname` stays missing: it is not replaced by a made-up value. Falco 0.33 and later always send it.

`enricher` in the core file changes every event before it is dispatched:

| Key | Effect |
| --- | --- |
| `custom_fields` | static output fields added to every event |
| `templated_fields` | output fields computed by a Go template over the event's output fields |
| `custom_tags` | tags added to every event |
| `bracket_replacer` | replaces `[` and `]` in output field names |
| `truncate_event_threshold` | off by default (`0`): above this event JSON size, string fields longer than `truncate_field_threshold` are cut. Cutting loses evidence, so set it only for a destination with a size limit |

## Metrics

`GET /metrics` on the ingestion listener serves Prometheus metrics. Counters of events count each event, a batch included.

| Metric | Meaning |
| --- | --- |
| `falcosidekick_ingest_requests_total{status}` | requests to `POST /`: `accepted`, or `invalid` (not a Falco event; a misconfigured sender shows here) |
| `falcosidekick_events_total{rule,priority,source,...}` | events accepted, with `priority` spelled as Falco does (`Warning`); `metrics.extra_labels` adds output fields as labels |
| `falcosidekick_output_events_total{output,status}` | events per output: `ok` delivered, `error` failed for good |
| `falcosidekick_output_dropped_events_total{output}` | events an output dropped because its queue was full |
| `falcosidekick_output_request_duration_seconds{output}` | duration of each delivery attempt, retries and failures included, a batch being one request |
| `falcosidekick_output_queue_length{output}`, `falcosidekick_output_queue_capacity{output}` | events waiting, and the queue size |
| `falcosidekick_output_status{output,status}` | 1 for the current status (`ok`, `idle`, `degraded`, `error`, `failed`), 0 for the others |
| `falcosidekick_output_circuit_state{output,state}` | 1 for the current circuit state (`closed`, `open`, `half-open`) |
| `falcosidekick_reloads_total{source,result}` | reloads by source (`file`, `ui`, `replica`) and result (`success`, `partial`, `failure`, `noop`) |
| `falcosidekick_reload_duration_seconds{source}`, `falcosidekick_reload_last_success_timestamp_seconds` | reload timing |
| `falcosidekick_label_overflows_total{label}` | values recorded as `other` because a label reached `metrics.max_label_values` (default 1000) |
| `falcosidekick_build_info{version,revision,goversion}` | always 1 |
| `go_*`, `process_*` | Go runtime and process metrics |

An alert on a failing output: `falcosidekick_output_status{status="error"} == 1`.

## Database

`database.backend` selects where outputs and the UI layout are stored:

| Backend | Use |
| --- | --- |
| `inmemory` (default) | nothing survives a restart; outputs from the output files are loaded again at start |
| `sqlite` | one instance; `database.sqlite.path` is a file on a local filesystem, created with mode 0600 (its `-wal` and `-shm` files take the same mode). Back it up with `sqlite3 <path> .backup <copy>`, or copy the file while Sidekick is stopped |
| `postgres` | several instances can share one database |

Postgres settings: `host`, `port` (5432), `database`, `user`, `password` or `password_file`, `sslmode` (`verify-full` by default; `disable`, `require`, `verify-ca`), `tls.ca_file` (system CAs when empty), `max_connections` (4), `poll_interval` (10s). Postgres 17 and 18 are tested. Sidekick creates and upgrades its tables (all named `falcosidekick_*`) at start; a database upgraded by a newer Sidekick is refused. `database.connect_timeout` (30s) bounds opening it. A postgres that does not answer yet, as when it starts together with Sidekick, is retried with backoff until then; a reply from postgres itself, such as a refused password or a missing database, stops startup at once, and so does a database still unreachable when the timeout ends.

With postgres, every instance applies the outputs another instance creates, changes or deletes through the API: it is notified at once, and checks the stored outputs every `poll_interval` in case a notification was lost (a lost listener connection reconnects and checks too). A change an instance cannot build, for example because a secret file is missing there, leaves its previous output running with status `degraded` and `last_warning` naming the version it could not apply; it is tried again at each check. Each check is counted in `falcosidekick_reloads_total{source="replica"}`, a change not applied with `result="failure"`. A write whose commit the database did not confirm answers 503 with "the change may have been applied": read the output again.

Outputs from the output files are written to the database at each start and reload; instances sharing a database should run the same output files, otherwise each start or reload of one replaces the outputs of the others, as happens briefly during a rolling update.

## Outputs from files and the API

Outputs from the output files are stored as file-provisioned. With `provisioning.allow_ui_updates: false`, the default, a `PUT` or `DELETE` on one of them through `/api/v1/pipeline/outputs/<name>`, which the UI also uses, answers 409 and changes nothing: change the file instead. With `true`, the API and the UI can change or delete them, and the files stay the source: the next start, or any later reload of the output files, applies the file version again, even when that output did not change in the files. A reload follows any change to an output file, including a change to another output, a change to a secret file the outputs read, or `SIGHUP`.

## Server TLS

`tls.enabled` serves HTTPS; `tls.mutual_tls` also requires a client certificate signed by `tls.ca_file`. `mutual_tls`, `cert_file`, `key_file` and `ca_file` need `tls.enabled: true`: set without it, startup fails. Client TLS towards outputs is set per output under `tls:`.
