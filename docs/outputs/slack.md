# Slack

Posts each event to a Slack incoming webhook. `host` defaults to `https://hooks.slack.com`; the webhook path, which is a credential, goes in `secret_endpoint`.

- The message is Block Kit inside one attachment, whose side bar has the priority color: the rule as heading, the output text, then the fields.
- The message text, which notifications show, is `[Priority] rule on hostname`, or `message_template` when set.
- The time renders in the reader's time zone, with RFC 3339 in UTC for clients that cannot.
- The webhook sets the channel, name and icon: Slack-app webhooks ignore overrides, so the output has none.

## Example

<!-- example -->
```yaml
outputs:
  slack:
    secret_endpoint_file: /etc/falcosidekick/secrets/slack/webhook-path
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
| `output_format` | one of `all`, `fields`, `text` | `all` | Content under the rule heading: `text` is the event output text, `fields` lists rule, priority, source, hostname, tags, time and output fields, `all` shows both. |
| `message_template` | string | - | Go template for the message text, which notifications show, applied to the event, such as `Rule {{ .Rule }} on {{ .Hostname }}`. Empty, or a template that fails, sends `[Priority] rule on hostname`. |
| `footer` | string | - | Slack markup shown at the bottom of the attachment, cut to 300 characters. Empty shows no footer. Suggested: `https://github.com/falcosecurity/falcosidekick`. |

Also takes the shared settings in [Query parameters](common.md#query-parameters), [HTTP authentication and headers](common.md#http-authentication-and-headers), [TLS](common.md#tls), [Delivery](common.md#delivery).

<!-- END GENERATED: settings -->
