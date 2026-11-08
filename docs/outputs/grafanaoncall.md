# Grafana OnCall

Posts each event to a formatted webhook integration of Grafana OnCall OSS (archived on 2026-03-24) or Grafana Cloud IRM, which use the same format. The token path goes in `secret_endpoint`; `bearer_token` sends a service account token when the integration requires one. Not probed at startup.

## Example

<!-- example -->
```yaml
outputs:
  grafanaoncall:
    host: https://oncall-prod-eu-west-0.grafana.net
    secret_endpoint_file: /etc/falcosidekick/secrets/grafanaoncall/integration-path
```

<!-- BEGIN GENERATED: settings -->
<!-- Generated from the output schema by `make docs`. Do not edit. -->

## Settings

Key in the output file: `grafanaoncall`. Category: Alerting and on-call. UI event source: no. Batching: no.

| Setting | Type | Default | Description |
| --- | --- | --- | --- |
| `host` | string, **required** | - | Address of the destination as scheme, host and optional port, such as `https://example.com:8443`; the path goes in the base path and endpoint. |
| `base_path` | string | - | Path prefix of every request, such as `/proxy/v2` when the destination sits behind a reverse proxy. |
| `secret_endpoint` | string, secret, **required** | - | Path the events are sent to, used instead of the endpoint when the path itself is a credential, as in a webhook URL; the API never returns it. Also accepted as `secret_endpoint_file`, the path of a file holding the value. |

Also takes the shared settings in [Query parameters](common.md#query-parameters), [HTTP authentication and headers](common.md#http-authentication-and-headers), [TLS](common.md#tls), [Delivery](common.md#delivery).

<!-- END GENERATED: settings -->
