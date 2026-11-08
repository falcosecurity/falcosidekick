# Loki

Pushes each event as a log line to Grafana Loki, at `/loki/api/v1/push` under `base_path`. `tenant` sets `X-Scope-OrgID` for a multi-tenant Loki. The health probe is `GET /ready`.

Stream labels are few and bounded, as Loki recommends:

| Label | Value |
| --- | --- |
| `source` | Event source, such as `syscall`. |
| `priority` | Priority as Falco writes it, such as `Warning`. |
| `level` | Priority in the names Grafana colors: `critical` (Emergency, Alert, Critical), `error`, `warning`, `info` (Notice, Informational) or `debug`. |
| `hostname` | Host that produced the event, when set. |
| `k8s_ns_name` | Kubernetes namespace, when the event has `k8s.ns.name`. |

The rule, tags, pod and other output fields are not labels. With `log_format: json`, the default, they are in the log line; filter on them with `| json`. `label_fields` adds other output fields as labels, named with `.` and `[` as `_`: `container.name` becomes `container_name`. Each distinct value makes a new stream, so add only fields with few values.

Tested with Loki 3.7.9 and 2.9.17.

## Example

<!-- example -->
```yaml
outputs:
  loki:
    host: http://loki:3100
    tenant: security
    label_fields:
      - container.name
```

<!-- BEGIN GENERATED: settings -->
<!-- Generated from the output schema by `make docs`. Do not edit. -->

## Settings

Key in the output file: `loki`. Category: Logs. UI event source: no. Batching: yes.

| Setting | Type | Default | Description |
| --- | --- | --- | --- |
| `host` | string, **required** | - | Address of the destination as scheme, host and optional port, such as `https://example.com:8443`; the path goes in the base path and endpoint. |
| `base_path` | string | - | Path prefix of every request, such as `/proxy/v2` when the destination sits behind a reverse proxy. |
| `endpoint` | string | `/loki/api/v1/push` | Path the events are sent to, after the base path. |
| `secret_endpoint` | string, secret | - | Path the events are sent to, used instead of the endpoint when the path itself is a credential, as in a webhook URL; the API never returns it. Also accepted as `secret_endpoint_file`, the path of a file holding the value. |
| `tenant` | string | - | Tenant ID sent in the `X-Scope-OrgID` header, for a multi-tenant Loki. Empty sends no header. |
| `log_format` | one of `json`, `text` | `json` | Content of each log line: `json` is the whole event as JSON, `text` is the event output text only. |
| `label_fields` | list of strings | - | Output field names, such as `container.name`, added as stream labels when the event has them, named with `.` and `[` as `_`: `container_name`. Every distinct value adds a stream, so list only fields with few values. A name that does not make a valid label name, or makes a built-in label, is refused. |

Also takes the shared settings in [Query parameters](common.md#query-parameters), [HTTP authentication and headers](common.md#http-authentication-and-headers), [TLS](common.md#tls), [Delivery](common.md#delivery), [Batching](common.md#batching).

<!-- END GENERATED: settings -->
