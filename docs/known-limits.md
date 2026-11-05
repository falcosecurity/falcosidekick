# Known limits of the v3 beta

- **API without authentication.** Writes are off by default. With `api.allow_writes: true`, anyone who reaches the port can change outputs.
- **In-memory storage.** The UI layout and outputs created through the API are lost on restart; output files provision outputs again.
- **Elasticsearch bulk.** One item rejected for good marks the whole batch as failed, and the batch is not split. A retry that crosses a daily index boundary, or a data stream rollover, can write a duplicate.
- **Kafka async.** Events count as sent once buffered; a later broker failure is counted as failed.
- **Health probe routes.** A proxy that answers 401, 403 or 404 on `/ready` (Loki) or `/-/healthy` (Alertmanager) but accepts deliveries makes startup fail. Elasticsearch with `create_index_template: true` fails startup while the server is unreachable.
- **Startup time.** Probes run one output after another, up to 5s each when a destination does not answer.
- **Counters** shown by the API restart from zero when an output is replaced by a reload or an API change; Prometheus counters keep the history.
