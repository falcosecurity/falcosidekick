# Microsoft Teams

Posts each event as an Adaptive Card to a Teams Workflows (Power Automate) webhook; the retired Office 365 connector `MessageCard` is not supported.

- `host` is required, since it varies per tenant. The workflow path goes in `secret_endpoint` and the `sig` query parameter must be a secret or a file.
- Workflows answers 202 once the flow run is queued: a run that fails later is visible only in the flow history.
- Messages are capped below the 28 KB Teams limit, dropping output fields first.
- Not probed at startup.

## Example

<!-- example -->
```yaml
outputs:
  teams:
    host: https://prod-00.westeurope.logic.azure.com:443
    secret_endpoint_file: /etc/falcosidekick/secrets/teams/workflow-path
    query_params:
      api-version:
        values: ["2016-06-01"]
      sp:
        values: ["/triggers/manual/run"]
      sv:
        values: ["1.0"]
      sig:
        files:
          - /etc/falcosidekick/secrets/teams/sig
```

<!-- BEGIN GENERATED: settings -->
<!-- Generated from the output schema by `make docs`. Do not edit. -->

## Settings

Key in the output file: `teams`. Category: Chat. UI event source: no. Batching: no.

| Setting | Type | Default | Description |
| --- | --- | --- | --- |
| `host` | string, **required** | - | Address of the destination as scheme, host and optional port, such as `https://example.com:8443`; the path goes in the base path and endpoint. |
| `base_path` | string | - | Path prefix of every request, such as `/proxy/v2` when the destination sits behind a reverse proxy. |
| `secret_endpoint` | string, secret, **required** | - | Path the events are sent to, used instead of the endpoint when the path itself is a credential, as in a webhook URL; the API never returns it. Also accepted as `secret_endpoint_file`, the path of a file holding the value. |
| `activity_image` | string | - | Absolute http or https URL of the image shown in the card header. Empty shows no image. Suggested: `https://raw.githubusercontent.com/falcosecurity/falcosidekick/master/imgs/falcosidekick_color.png`. |
| `output_format` | one of `all`, `text`, `fields` | `all` | Content of the card: `text` is the event output text, `fields` lists rule, priority, source, hostname, output fields and tags, `all` shows both. |

Also takes the shared settings in [Query parameters](common.md#query-parameters), [HTTP authentication and headers](common.md#http-authentication-and-headers), [TLS](common.md#tls), [Delivery](common.md#delivery).

<!-- END GENERATED: settings -->
