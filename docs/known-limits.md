# Known limits

- **API without authentication.** Writes are off by default. With `api.allow_writes: true`, anyone who reaches the port can change outputs, and so send events, and secrets stored for outputs, to a destination of their choice. `api.secret_dirs` limits only which files a write can name.
- **In-memory storage by default.** With `database.backend: inmemory` the UI layout and outputs created through the API are lost on restart; output files provision outputs again. `sqlite` and `postgres` keep them (see [configuration](configuration.md#database)).
- **One instance per sqlite file.** Several instances share outputs only through postgres.
- **Instances sharing postgres need the same output files.** Each start and reload stores this instance's output files; during a rolling update that changes them, instances overwrite each other's file outputs until they all run the new files.
- **No secret values in sqlite or postgres.** With these backends a secret must be a file path (`<field>_file`, header and query `files`); inline values are refused.
- **Elasticsearch data streams.** A retry after a data stream rollover can write a duplicate: ids are checked only in the current backing index.
- **Whole-batch retries for SQS, Pub/Sub, Kafka and Redis.** Their batch errors do not name the failed events: when part of a batch fails, the whole batch is sent again, or fails whole when every failed part is permanent. PolicyReport and Elasticsearch count the delivered events as sent and send again only the failed ones.
- **No startup probe** for Webhook, Slack, Teams, Grafana OnCall, PagerDuty and CloudEvents: their APIs have no request without side effects, so a wrong address or credential shows on the first delivery.
- **Teams** answers 202 when the workflow run is queued; a run that fails later shows only in the flow history.
- **Discontinued services.** Atlassian ends Opsgenie on 2027-04-05. Grafana OnCall OSS is archived; Grafana Cloud IRM accepts the same webhook.
- **`Retry-After` is not honoured.** A 429 or 503 is retried with the output's own exponential backoff, bounded by `retry.max_attempts` and the circuit breaker, whatever delay the destination asks for.
- **No start without the database.** With `sqlite` or `postgres`, Sidekick waits for the database up to `database.connect_timeout` (30s by default), then stops.
- **Some secret changes need a restart.** A new Secret added to the chart's `secrets` is mounted only by a `helm upgrade`; a new server TLS certificate or postgres password is read only at start, so it needs a restart.

## Beta

- **Pre-release image tags only.** `3.0.0-beta.1` and `3.0.0-beta.1-slim`, plus the `v3-main` builds; no `3`, `3.0` or `v3-latest` before 3.0.0, and `latest` is still v2. See [install](install.md#images).
- **The chart needs `--devel`.** The v3 chart, `1.0.0-beta.1`, is a pre-release; without `--devel` Helm installs the v2 chart, `0.x`.
- **The Falco chart still installs v2.** Its `falcosidekick` dependency stays on the `0.x` chart; install the v3 chart on its own.
- **The Falco operator does not deploy v3 yet.**
