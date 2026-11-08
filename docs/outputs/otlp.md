# OpenTelemetry (OTLP)

One output for logs and metrics: each section present enables that signal, with its own `endpoint`, `protocol` (`http/protobuf` or `grpc`), headers, TLS, `timeout` and `compression`. `OTEL_*` environment variables have no effect.

- Logs: one record per event, event name `falco.alert`, severity from the priority.
- Metrics: the cumulative counter `falcosecurity.falco.rules.matches` by rule, priority, source, hostname and tags, plus `extra_attributes`; a retried event is not counted twice, also when the retry is for another signal. The output remembers the last 100,000 counted events: a retry that comes after more new events than that counts its events again. Beyond 2000 attribute combinations the SDK adds to one overflow series (`otel.metric.overflow`).
- Resource `service.name` is `falcosidekick`. Attributes use the `falco.` prefix; output fields keep their names.
- Not probed at startup: OTLP has no request that exports nothing.
- `http/protobuf` uses the same HTTP client as the other HTTP outputs, so redirects to another origin are refused, and it follows `HTTP_PROXY`; `grpc` follows `HTTPS_PROXY`.
- There is no traces signal: a Falco event is a point in time, not an operation with a duration and a parent, so it is a log record. A `traces` section is refused.
- Failures follow the [OTLP retry rules](https://opentelemetry.io/docs/specs/otlp/#failures): gRPC retries `CANCELLED`, `DEADLINE_EXCEEDED`, `ABORTED`, `OUT_OF_RANGE`, `UNAVAILABLE`, `DATA_LOSS`, and `RESOURCE_EXHAUSTED` when the collector sends `RetryInfo`; HTTP retries 429, 502, 503 and 504. A partial success is not retried. When one signal fails and can be retried, the retry exports every enabled signal again, including those already accepted in full or in part, so the collector can receive them twice; the event fails for good only when every failed signal does.

Tested with the OpenTelemetry Collector contrib 0.164.0.

## Example

<!-- example -->
```yaml
outputs:
  otlp:
    logs:
      endpoint: http://otel-collector:4318
    metrics:
      endpoint: http://otel-collector:4318
      extra_attributes: [k8s.ns.name]
```

<!-- BEGIN GENERATED: settings -->
<!-- Generated from the output schema by `make docs`. Do not edit. -->

## Settings

Key in the output file: `otlp`. Category: Observability. UI event source: no. Batching: yes.

| Setting | Type | Default | Description |
| --- | --- | --- | --- |
| `logs.endpoint` | string | - | Collector URL, `http://` or `https://`, without credentials, query or fragment. With `http/protobuf` an empty path becomes `/v1/logs`; with `grpc` no path is allowed. |
| `logs.protocol` | one of `http/protobuf`, `grpc` | `http/protobuf` | OTLP transport: protobuf over HTTP or gRPC. |
| `logs.compression` | one of `none`, `gzip` | `none` | Compression of export requests. |
| `logs.timeout` | string | `10s` | Go duration, such as `10s`, bounding each export request and the shutdown of this signal. `0` uses the default. |
| `logs.headers` | map by name | - | Extra headers sent with every request, by header name. Names are case-insensitive; headers the HTTP transport owns, such as `Host` or `Content-Length`, are refused. |
| `logs.headers.<name>.values` | list of strings | - | Values of the header, sent as written; the API returns them. |
| `logs.headers.<name>.secrets` | list of strings, secret | - | Values of the header the API never returns. |
| `logs.headers.<name>.files` | list of strings, file path | - | Files whose content, without surrounding whitespace, is a value of the header; read at every request. |
| `logs.tls.insecure_skip_verify` | boolean | `false` | Accepts any server certificate. The connection can then be intercepted: use it only for tests. |
| `logs.tls.ca_file` | string, file path | - | PEM file with the certificate authorities that sign the server certificate. Empty uses the system trust store. |
| `logs.tls.cert_file` | string, file path | - | PEM client certificate for mutual TLS, set together with the key file. |
| `logs.tls.key_file` | string, file path | - | PEM private key of the client certificate. |
| `logs.tls.server_name` | string | - | Name checked against the server certificate when it differs from the host the output connects to. |
| `metrics.endpoint` | string | - | Collector URL, `http://` or `https://`, without credentials, query or fragment. With `http/protobuf` an empty path becomes `/v1/metrics`; with `grpc` no path is allowed. |
| `metrics.protocol` | one of `http/protobuf`, `grpc` | `http/protobuf` | OTLP transport: protobuf over HTTP or gRPC. |
| `metrics.compression` | one of `none`, `gzip` | `none` | Compression of export requests. |
| `metrics.timeout` | string | `10s` | Go duration, such as `10s`, bounding each export request and the shutdown of this signal. `0` uses the default. |
| `metrics.headers` | map by name | - | Extra headers sent with every request, by header name. Names are case-insensitive; headers the HTTP transport owns, such as `Host` or `Content-Length`, are refused. |
| `metrics.headers.<name>.values` | list of strings | - | Values of the header, sent as written; the API returns them. |
| `metrics.headers.<name>.secrets` | list of strings, secret | - | Values of the header the API never returns. |
| `metrics.headers.<name>.files` | list of strings, file path | - | Files whose content, without surrounding whitespace, is a value of the header; read at every request. |
| `metrics.tls.insecure_skip_verify` | boolean | `false` | Accepts any server certificate. The connection can then be intercepted: use it only for tests. |
| `metrics.tls.ca_file` | string, file path | - | PEM file with the certificate authorities that sign the server certificate. Empty uses the system trust store. |
| `metrics.tls.cert_file` | string, file path | - | PEM client certificate for mutual TLS, set together with the key file. |
| `metrics.tls.key_file` | string, file path | - | PEM private key of the client certificate. |
| `metrics.tls.server_name` | string | - | Name checked against the server certificate when it differs from the host the output connects to. |
| `metrics.extra_attributes` | list of strings | - | Output field names, such as `k8s.ns.name`, added to the counter attributes when the event has them; each distinct value adds a series. Keys the output sets itself, such as `falco.rule` or `host.name`, are refused. |

Also takes the shared settings in [Delivery](common.md#delivery), [Batching](common.md#batching).

<!-- END GENERATED: settings -->
