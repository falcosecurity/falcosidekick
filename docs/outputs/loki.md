# Loki

Pushes each event as a log line to Grafana Loki, at `/loki/api/v1/push` under `base_path`. `tenant` sets `X-Scope-OrgID` for a multi-tenant Loki. The health probe is `GET /ready`.

Tested with Loki 3.7.9 and 2.9.17.

## Example

<!-- example -->
```yaml
outputs:
  loki:
    host: http://loki:3100
    tenant: security
    extra_labels: k8s.ns.name,k8s.pod.name
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
| `extra_labels` | string | - | Output field names, separated by commas, such as `container.id,proc.name`, added as stream labels when the event has them. Characters other than letters, digits and `_` in label names become `_`. |

Also takes the shared settings in [Query parameters](common.md#query-parameters), [HTTP authentication and headers](common.md#http-authentication-and-headers), [TLS](common.md#tls), [Delivery](common.md#delivery), [Batching](common.md#batching).

<!-- END GENERATED: settings -->
