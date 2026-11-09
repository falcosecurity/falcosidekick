# Apache Kafka

Writes each event as a record to a Kafka topic.

- Each delivery waits for the broker acknowledgement, so the counters are exact; the pipeline queue absorbs bursts. `producer.delivery_timeout` (minimum 1s) bounds each record and the flush on shutdown.
- Without `producer.compression` the client keeps its default, `snappy`, or no compression for brokers that do not support it.
- The client ID is `falcosidekick` unless `producer.client_id` is set.
- Idempotent writes are on with `required_acks: all`. With them a record already sent stays with the client until the broker answers, so a delivery that runs out of time is not reported as failed after Kafka wrote it. With `one` or `none` it can be, and the retry writes it again.
- Startup asks the brokers for the default `topic`: a missing topic, unless `producer.auto_create_topic` is set, or a topic the client may not access stops startup. Topics taken from `topic_field` are not checked.
- A failed record is retried unless Kafka marks its error non-retriable; a batch fails for good only when every failed record does.
- Within `delivery_timeout` the client retries a record itself, for example across a leader change; with idempotent writes the broker drops those duplicates, which a pipeline retry, as a new record, cannot get.
- Client warnings and errors (connection, TLS, SASL) go to the Falcosidekick log with the broker, topic, partition and group only.
- `auth.sasl` is spelled as Kafka does: `PLAIN`, `SCRAM-SHA-256` or `SCRAM-SHA-512`.
- `tls.enabled: true` connects over TLS; the other `tls` settings without it are refused at startup instead of being ignored.

Tested with Kafka 4.4.0 and 3.9.2.

## Example

<!-- example -->
```yaml
outputs:
  kafka:
    brokers:
      - kafka-0.kafka:9092
      - kafka-1.kafka:9092
    topic: falco
    tls:
      enabled: true
    auth:
      sasl: SCRAM-SHA-512
      username: falcosidekick
      password_file: /etc/falcosidekick/secrets/kafka/password
```

<!-- BEGIN GENERATED: settings -->
<!-- Generated from the output schema by `make docs`. Do not edit. -->

## Settings

Key in the output file: `kafka`. Category: Queues and streams. UI event source: no. Batching: yes.

| Setting | Type | Default | Description |
| --- | --- | --- | --- |
| `brokers` | list of strings, **required** | - | Seed brokers as `host:port`, without scheme or path. The client discovers the rest of the cluster from them. |
| `topic` | string, **required** | - | Topic for events without a `topic_field` value. Startup checks that it exists and is writable. |
| `topic_field` | string | - | Output field, such as `k8s.ns.name`, whose string value names the topic. Events without a non-empty string value use `topic`. These topics are not checked at startup. |
| `message_key` | string | - | Record key used when `message_key_field` gives no value; records with the same key go to the same partition. Empty sends records without a key, spread across partitions. |
| `message_key_field` | string | - | Output field whose non-empty string value is the record key. Otherwise `message_key` applies. |
| `auth.sasl` | one of `PLAIN`, `SCRAM-SHA-256`, `SCRAM-SHA-512` | - | SASL mechanism for broker authentication, spelled as Kafka does: `PLAIN`, `SCRAM-SHA-256` or `SCRAM-SHA-512`. Empty disables SASL; any mechanism requires username and password. |
| `auth.username` | string | - | User for SASL authentication. |
| `auth.password` | string, secret | - | Password for SASL authentication. Also accepted as `auth.password_file`, the path of a file holding the value. |
| `producer.compression` | one of `none`, `gzip`, `snappy`, `lz4`, `zstd` | - | Codec for record batches sent to the brokers. Empty keeps the client default: `snappy`, or no compression for brokers that do not support it. |
| `producer.required_acks` | one of `all`, `one`, `none` | `all` | Acknowledgement the brokers give before a record counts as written: all in-sync replicas, the leader, or none. Idempotent writes are enabled only with `all`. |
| `producer.client_id` | string | `falcosidekick` | Client ID sent to the brokers, visible in their logs and quotas. |
| `producer.auto_create_topic` | boolean | `false` | Asks the brokers to create a missing topic, if they allow it, and lets startup accept a missing default topic. |
| `producer.delivery_timeout` | string | `10s` | Go duration, such as `10s`, bounding the delivery of each record, client retries included, and the flush on shutdown. At least `1s`. |
| `tls.enabled` | boolean | `false` | Connects over TLS. The other `tls` settings are refused unless this is set. |

Also takes the shared settings in [TLS](common.md#tls), [Delivery](common.md#delivery), [Batching](common.md#batching).

<!-- END GENERATED: settings -->
