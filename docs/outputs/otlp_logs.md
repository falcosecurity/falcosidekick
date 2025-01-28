# OTEL Logs

- **Category**: Logs
- **Website**: <https://opentelemetry.io/docs/concepts/signals/logs/>

## Table of content

- [OTEL Logs](#otel-logs)
  - [Table of content](#table-of-content)
  - [Configuration](#configuration)
  - [Example of config.yaml](#example-of-configyaml)
  - [Additional info](#additional-info)

## Configuration

|           Setting           |           Env var           |       Default value        |                                                             Description                                                             |
| --------------------------- | --------------------------- | -------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `otlp.logs.endpoint`        | `OTLP_LOGS_ENDPOINT`        |                            | OTLP endpoint in the form of http://{domain or ip}:4318/v1/logs                                                                     |
| `otlp.logs.protocol`        | `OTLP_LOGS_PROTOCOL`        | `http/protobuf` (from SDK) | OTLP Protocol: `http/protobuf`, `grpc`                                                                                              |
| `otlp.logs.timeout`         | `OTLP_LOGS_TIMEOUT`         | `10000` (from SDK)         | Timeout value in milliseconds                                                                                                       |
| `otlp.logs.headers`         | `OTLP_LOGS_HEADERS`         |                            | List of headers to apply to all outgoing logs in the form of "some-key=some-value,other-key=other-value"                            |
| `otlp.logs.synced`          | `OTLP_LOGS_SYNCED`          | `false`                    | Set to `true` if you want logs to be sent synchronously                                                                             |
| `otlp.logs.minimumpriority` | `OTLP_LOGS_MINIMUMPRIORITY` | `""` (=`debug`)            | minimum priority of event for using this output, order is `emergency,alert,critical,error,warning,notice,informational,debug or ""` |
| `otlp.logs.checkcert`       | `OTLP_LOGS_CHECKCERT`       | `false`                    | Set if you want to skip TLS certificate validation                                                                                  |
| `otlp.logs.duration`        | `OTLP_LOGS_DURATION`        | `1000`                     | Artificial span duration in milliseconds (as Falco doesn't provide an ending timestamp)                                             |
| `otlp.logs.extraenvvars`    | `OTLP_LOGS_EXTRAENVVARS`    |                            | Extra env vars (override the other settings)                                                                                        |

> [!NOTE]
For the extra Env Vars values see [standard `OTEL_*` environment variables](https://opentelemetry.io/docs/specs/otel/configuration/sdk-environment-variables/)

## Example of config.yaml

```yaml
otlp:
  logs:
    # endpoint: "" # OTLP endpoint in the form of http(s)://{domain or ip}:4318(/v1/logs), if not empty, OTLP Traces output is enabled
    protocol: "" # OTLP protocol: http/protobuf, grpc (default: "" which uses SDK default: "http/protobuf")
    # timeout: "" # OTLP timeout: timeout value in milliseconds (default: "" which uses SDK default: 10000)
    # headers: "" # OTLP headers: list of headers to apply to all outgoing traces in the form of "some-key=some-value,other-key=other-value" (default: "")
    # extraenvvars: # Extra env vars (override the other settings)
      # OTEL_EXPORTER_OTLP_TRACES_TIMEOUT: 10000
      # OTEL_EXPORTER_OTLP_TIMEOUT: 10000
    # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
    # checkcert: true # Set if you want to skip TLS certificate validation (default: true)
```

## Additional info

> [!WARNING]
Because of the way the OTEL SDK is structured, the OTLP outputs don't appear in the metrics (Prometheus, Statsd, ...) 
and the error logs just specify `OTEL` as output.
