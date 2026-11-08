# CloudEvents

Sends each event as CloudEvents 1.0 over HTTP in binary mode. The headers are `ce-specversion`, `ce-id` (the event UUID), `ce-source` (`source`), `ce-type` (`org.falco.rule.output.v1`), `ce-time` (the event time), plus `ce-priority`, `ce-rule`, `ce-eventsource`, `ce-hostname` and the configured `extensions` (names `[a-z0-9]+`). The body is the event JSON. Not probed at startup.

`source` is required and has no default: it names the context that produced the events, such as `/falcosidekick` or `/cluster/prod/falcosidekick`, so receivers can tell deployments apart.

## Example

<!-- example -->
```yaml
outputs:
  cloudevents:
    host: http://broker-ingress.knative-eventing.svc.cluster.local
    endpoint: /security/default
    source: /cluster/prod-eu/falcosidekick
    extensions:
      cluster: prod-eu
```

<!-- BEGIN GENERATED: settings -->
<!-- Generated from the output schema by `make docs`. Do not edit. -->

## Settings

Key in the output file: `cloudevents`. Category: Webhooks. UI event source: no. Batching: no.

| Setting | Type | Default | Description |
| --- | --- | --- | --- |
| `host` | string, **required** | - | Address of the destination as scheme, host and optional port, such as `https://example.com:8443`; the path goes in the base path and endpoint. |
| `base_path` | string | - | Path prefix of every request, such as `/proxy/v2` when the destination sits behind a reverse proxy. |
| `endpoint` | string | `/` | Path the events are sent to, after the base path. |
| `secret_endpoint` | string, secret | - | Path the events are sent to, used instead of the endpoint when the path itself is a credential, as in a webhook URL; the API never returns it. Also accepted as `secret_endpoint_file`, the path of a file holding the value. |
| `source` | string, **required** | - | Value of the `source` attribute of every event, a URI reference naming the context that produced it, such as `/falcosidekick` or `/cluster/prod/falcosidekick`. Suggested: `/falcosidekick`. |
| `extensions` | map by name | - | Extension attributes sent as `ce-` headers with every event, by name of lowercase letters and digits. They replace the built-in `priority`, `rule`, `eventsource` and `hostname`; spec attributes such as `id` are refused. |

Also takes the shared settings in [Query parameters](common.md#query-parameters), [HTTP authentication and headers](common.md#http-authentication-and-headers), [TLS](common.md#tls), [Delivery](common.md#delivery).

<!-- END GENERATED: settings -->
