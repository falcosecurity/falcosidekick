# Known limits

- **API without authentication.** Writes are off by default. With `api.allow_writes: true`, anyone who reaches the port can change outputs, and so send events, and secrets stored for outputs, to a destination of their choice. `api.secret_dirs` limits only which files a write can name.
- **In-memory storage by default.** With `database.backend: inmemory` the UI layout and outputs created through the API are lost on restart; output files provision outputs again. `sqlite` and `postgres` keep them (see [configuration](configuration.md#database)).
- **One instance per sqlite file.** Several instances share outputs only through postgres.
- **Instances sharing postgres need the same output files.** Each start and reload stores this instance's output files; during a rolling update that changes them, instances overwrite each other's file outputs until they all run the new files.
- **No secret values in sqlite or postgres.** With these backends a secret must be a file path (`<field>_file`, header and query `files`); inline values are refused.
- **Elasticsearch bulk.** One item rejected for good marks the whole batch as failed, and the batch is not split. A retry that crosses a daily index boundary, or a data stream rollover, can write a duplicate.
- **No startup probe** for Webhook, Slack, Teams, Grafana OnCall, PagerDuty and CloudEvents: their APIs have no request without side effects, so a wrong address or credential shows on the first delivery.
- **Teams** answers 202 when the workflow run is queued; a run that fails later shows only in the flow history.
- **Discontinued services.** Atlassian ends Opsgenie on 2027-04-05. Grafana OnCall OSS is archived; Grafana Cloud IRM accepts the same webhook.
