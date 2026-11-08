# Slack

Posts each event to a Slack incoming webhook. `host` defaults to `https://hooks.slack.com`; the webhook path, which is a credential, goes in `secret_endpoint`.

## Example

<!-- example -->
```yaml
outputs:
  slack:
    secret_endpoint_file: /etc/falcosidekick/secrets/slack/webhook-path
    channel: "#security-alerts"
    output_format: all
    runtime:
      minimum_priority: warning
```

The file holds the path of the webhook URL, such as `/services/T000/B000/XXXX`.

<!-- BEGIN GENERATED: settings -->
<!-- Generated from the output schema by `make docs`. Do not edit. -->

## Settings

Key in the output file: `slack`. Category: Chat. UI event source: no. Batching: no.

| Setting | Type | Default | Description |
| --- | --- | --- | --- |
| `host` | string | `https://hooks.slack.com` | Address of the destination as scheme, host and optional port, such as `https://example.com:8443`; the path goes in the base path and endpoint. |
| `base_path` | string | - | Path prefix of every request, such as `/proxy/v2` when the destination sits behind a reverse proxy. |
| `secret_endpoint` | string, secret, **required** | - | Path the events are sent to, used instead of the endpoint when the path itself is a credential, as in a webhook URL; the API never returns it. Also accepted as `secret_endpoint_file`, the path of a file holding the value. |
| `channel` | string | - | Channel the messages are posted to, such as `#falco`, when the webhook allows it. Empty uses the webhook's channel. |
| `bot_username` | string | - | Name shown as the sender of the messages, when the webhook allows it. Empty uses the webhook's name. |
| `icon_url` | string | - | URL of the image shown as the sender icon. Empty uses the webhook's icon. |
| `icon_emoji` | string | - | Emoji shown as the sender icon, written as `:name:`. Empty uses the webhook's icon. |
| `output_format` | one of `all`, `fields`, `text` | `all` | Content of the attachment: `text` is the event output text, `fields` lists rule, priority, source, hostname, tags, output fields and time, `all` shows both. |
| `message_format` | string | - | Go template for a message text shown above the attachment, applied to the event, such as `Rule {{ .Rule }} on {{ .Hostname }}`. Empty sends no message text. |
| `footer` | string | - | Text shown under the attachment, cut to 300 characters. Empty uses the default. |

Also takes the shared settings in [Query parameters](common.md#query-parameters), [HTTP authentication and headers](common.md#http-authentication-and-headers), [TLS](common.md#tls), [Delivery](common.md#delivery).

<!-- END GENERATED: settings -->
