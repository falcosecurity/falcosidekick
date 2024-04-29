# Rocketchat


- **Category**: Chat/Messaging
- **Website**: https://rocket.chat

## Table of content

- [Rocketchat](#rocketchat)
  - [Table of content](#table-of-content)
  - [Configuration](#configuration)
  - [Example of config.yaml](#example-of-configyaml)
  - [Additional info](#additional-info)
    - [Message Formatting](#message-formatting)

## Configuration


| Setting                      | Env var                      | Default value                                                                                       | Description                                                                                                                                                                                                                                                                    |
| ---------------------------- | ---------------------------- | --------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `rocketchat.webhookurl`      | `ROCKETCHAT_WEBHOOKURL`      |                                                                                                     | Rocketchat WebhookURL (ex: https://hooks.rocketchat.com/services/XXXX/YYYY/ZZZZ), if not empty, Rocketchat output is **enabled**                                                                                                                                               |
| `rocketchat.icon`            | `ROCKETCHAT_ICON`            | `https://raw.githubusercontent.com/falcosecurity/falcosidekick/master/imgs/falcosidekick_color.png` | Rocketchat icon (avatar)                                                                                                                                                                                                                                                       |
| `rocketchat.username`        | `ROCKETCHAT_USERNAME`        | `Falcosidekick`                                                                                     | Rocketchat username                                                                                                                                                                                                                                                            |
| `rocketchat.outputformat`    | `ROCKETCHAT_OUTPUTFORMAT`    | `all`                                                                                               | Rocketchat message format: `all`, `text`, `field`                                                                                                                                                                                                                              |
| `rocketchat.messageformat`   | `ROCKETCHAT_MESSAGEFORMAT`   |                                                                                                     | A Go template to format Rocketchat Text above Attachment, displayed in addition to the output from `ROCKETCHAT_OUTPUTFORMAT`, see [Message Formatting](#message-formatting) in the README for details. If empty, no Text is displayed before Attachment. |
| `rocketchat.mutualtls`       | `ROCKETCHAT_MUTUALTLS`       | `false`                                                                                             | Authenticate to the output with TLS, if true, checkcert flag will be ignored (server cert will always be checked)                                                                                                                                                              |
| `rocketchat.checkcert`       | `ROCKETCHAT_CHECKCERT`       | `true`                                                                                              | check if ssl certificate of the output is valid                                                                                                                                                                                                                                | `rocketchat.minimumpriority` | `ROCKETCHAT_MINIMUMPRIORITY` | `""` (= `debug`)                                                                                    | Minimum priority of event for using this output, order is `emergency,alert,critical,error,warning,notice,informational,debug or ""`
| `rocketchat.minimumpriority` | `ROCKETCHAT_MINIMUMPRIORITY` | `""` (= `debug`)                                                                                    | Minimum priority of event for using this output, order is `emergency,alert,critical,error,warning,notice,informational,debug or ""`                                                                                                                                            |


> [!NOTE]
The Env var values override the settings from yaml file.

## Example of config.yaml

```yaml
rocketchat:
  webhookurl: "" # Rocketchat WebhookURL (ex: http://XXXX/hooks/YYYY), if not empty, Rocketchat output is enabled
  # icon: "" # Rocketchat icon (avatar)
  # username: "" # Rocketchat username (default: Falcosidekick)
  # outputformat: "all" # all (default), text, fields
  # messageformat: "Alert : rule *{{ .Rule }}* triggered by user *{{ index .OutputFields \"user.name\" }}*" # a Go template to format Rocketchat Text above Attachment, displayed in addition to the output from `ROCKETCHAT_OUTPUTFORMAT`. If empty, no Text is displayed before Attachment.
  # mutualtls: false # if true, checkcert flag will be ignored (server cert will always be checked)
  # checkcert: true # check if ssl certificate of the output is valid (default: true)
  # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
```

## Additional info

### Message Formatting

The `ROCKETCHAT_MESSAGEFORMAT` environment variable and `rocketchat.messageformat` YAML value accept a [Go template](https://golang.org/pkg/text/template/) which can be used to format the text of a Rocketchat alert.
These templates are evaluated on the JSON data from each Falco event. The following fields are available:

| Template Syntax                              | Description                                                                                                                                                        |
| -------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `{{ .Output }}`                              | A formatted string from Falco describing the event.                                                                                                                |
| `{{ .Priority }}`                            | The priority of the event, as a string.                                                                                                                            |
| `{{ .Rule }}`                                | The name of the rule that generated the event.                                                                                                                     |
| `{{ .Time }}`                                | The timestamp when the event occurred.                                                                                                                             |
| `{{ index .OutputFields \"<field name>\" }}` | A map of additional optional fields emitted depending on the event. These may not be present for every event, in which case they expand to the string `<no value>` |

Go templates also support some basic methods for text manipulation which can be used to improve the clarity of alerts - see the documentation for details.