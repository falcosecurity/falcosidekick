# Known limits

- **API without authentication.** Writes are off by default. With `api.allow_writes: true`, anyone who reaches the port can change outputs.
- **In-memory storage.** The UI layout and outputs created through the API are lost on restart; output files provision outputs again.
- **Elasticsearch bulk.** One item rejected for good marks the whole batch as failed, and the batch is not split. A retry that crosses a daily index boundary, or a data stream rollover, can write a duplicate.
- **Kafka async.** Events count as sent once buffered; a later broker failure is counted as failed.
- **No startup probe** for Webhook and Slack: their endpoints accept only POST, so a wrong address or credential shows on the first delivery.
