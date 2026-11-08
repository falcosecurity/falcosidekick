# Discord

Posts each event as an embed to a Discord webhook. `host` defaults to `https://discord.com`; the webhook path with its token goes in `secret_endpoint`. Startup reads the webhook with `GET`, which posts nothing: a wrong token or a deleted webhook stops startup.

- The embed title is the rule, its timestamp the event time, its color the priority's.
- Embeds stay within the documented limits: title 256 characters, description 4096, 25 fields of up to 1024, 6000 in all. Output fields are dropped first.

## Example

<!-- example -->
```yaml
outputs:
  discord:
    secret_endpoint_file: /etc/falcosidekick/secrets/discord/webhook-path
    avatar_url: https://raw.githubusercontent.com/falcosecurity/falcosidekick/master/imgs/falcosidekick_color.png
```

The file holds the path of the webhook URL, such as `/api/webhooks/123/abc`.

<!-- BEGIN GENERATED: settings -->
<!-- Generated from the output schema by `make docs`. Do not edit. -->

## Settings

Key in the output file: `discord`. Category: Chat. UI event source: no. Batching: no.

| Setting | Type | Default | Description |
| --- | --- | --- | --- |
| `host` | string | `https://discord.com` | Address of the destination as scheme, host and optional port, such as `https://example.com:8443`; the path goes in the base path and endpoint. |
| `base_path` | string | - | Path prefix of every request, such as `/proxy/v2` when the destination sits behind a reverse proxy. |
| `secret_endpoint` | string, secret, **required** | - | Path the events are sent to, used instead of the endpoint when the path itself is a credential, as in a webhook URL; the API never returns it. Also accepted as `secret_endpoint_file`, the path of a file holding the value. |
| `avatar_url` | string | - | Absolute http or https URL of the image shown as the avatar of every message. Empty uses the webhook's avatar. Suggested: `https://raw.githubusercontent.com/falcosecurity/falcosidekick/master/imgs/falcosidekick_color.png`. |

Also takes the shared settings in [Query parameters](common.md#query-parameters), [HTTP authentication and headers](common.md#http-authentication-and-headers), [TLS](common.md#tls), [Delivery](common.md#delivery).

<!-- END GENERATED: settings -->
