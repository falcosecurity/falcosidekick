# Zoho Cliq

- **Category**: Chat
- **Website**: https://www.zoho.com/cliq/

## Table of content

- [Zoho Cliq](#zoho-cliq)
  - [Table of content](#table-of-content)
  - [Configuration](#configuration)
  - [Example of config.yaml](#example-of-configyaml)
  - [Additional info](#additional-info)
    - [Message Formatting](#message-formatting)
  - [Screenshots](#screenshots)

## Configuration

| Setting                | Env var                | Default value    | Description                                                                                                                                                                                                                                            |
| ---------------------- | ---------------------- | ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `cliq.webhookurl`      | `CLIQ_WEBHOOKURL`      |                  | WebhookURL (ex: https://cliq.zoho.eu/api/v2/channelsbyname/XXXX/message?zapikey=YYYY), if not empty, Cliq output is **enabled**                                                                                                                        |
| `cliq.icon`            | `CLIQ_ICON`            |                  | Cliq icon (avatar)                                                                                                                                                                                                                                     |
| `cliq.useemoji`        | `CLIQ_USEEMOJI`        | `true`           | Prefix message text with an emoji                                                                                                                                                                                                                      |
| `cliq.outputformat`    | `CLIQ_OUTPUTFORMAT`    | `all`            | `all`, `text`, `fields`                                                                                                                                                                                                                                |
| `cliq.messageformat`   | `CLIQ_MESSAGEFORMAT`   |                  | A Go template to format Cliq Text above Attachment, displayed in addition to the output from `CLIQ_OUTPUTFORMAT`, see [Message Formatting](#message-formatting) in the README for details. If empty, no Text is displayed before Attachment. |
| `cliq.minimumpriority` | `CLIQ_MINIMUMPRIORITY` | `""` (= `debug`) | Minimum priority of event for using this output, order is `emergency,alert,critical,error,warning,notice,informational,debug or ""`                                                                                                                    |

> [!NOTE]
The Env var values override the settings from yaml file.

## Example of config.yaml

```yaml
cliq:
  webhookurl: "" # WebhookURL (ex: https://cliq.zoho.eu/api/v2/channelsbyname/XXXX/message?zapikey=YYYY), if not empty, Cliq output is enabled
  # icon: "" # Cliq icon (avatar)
  # useemoji: true # Prefix message text with an emoji
  # outputformat: "all" # all (default), text, fields
  # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
  # messageformat: 'Alert : rule *{{ .Rule }}* triggered by user *{{ index.OutputFields "user.name" }}*' # a Go template to format Cliq Text above Table, displayed in addition to the output from `CLIQ_OUTPUTFORMAT`, see [Slack Message Formatting](#slack-message-formatting) in the README for details. If empty, no Text is displayed before Table.
```

## Additional info

### Message Formatting

The `CLIQ_MESSAGEFORMAT` environment variable and `cliq.messageformat` YAML value accept a [Go template](https://golang.org/pkg/text/template/) which can be used to format the text of a Cliq alert.
These templates are evaluated on the JSON data from each Falco event. The following fields are available:

| Template Syntax                              | Description                                                                                                                                                        |
| -------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `{{ .Output }}`                              | A formatted string from Falco describing the event.                                                                                                                |
| `{{ .Priority }}`                            | The priority of the event, as a string.                                                                                                                            |
| `{{ .Rule }}`                                | The name of the rule that generated the event.                                                                                                                     |
| `{{ .Time }}`                                | The timestamp when the event occurred.                                                                                                                             |
| `{{ index .OutputFields \"<field name>\" }}` | A map of additional optional fields emitted depending on the event. These may not be present for every event, in which case they expand to the string `<no value>` |

Go templates also support some basic methods for text manipulation which can be used to improve the clarity of alerts - see the documentation for details.

## Screenshots
