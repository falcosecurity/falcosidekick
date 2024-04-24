# Azure EventHub

- **Category**: Message queue / Streaming
- **Website**: https://azure.microsoft.com/en-in/services/event-hubs/²
## Table of content

- [Azure EventHub](#azure-eventhub)
  - [Table of content](#table-of-content)
  - [Configuration](#configuration)
  - [Example of config.yaml](#example-of-configyaml)
  - [Additional info](#additional-info)
  - [Screenshots](#screenshots)

## Configuration

| Setting                          | Env var                          | Default value    | Description                                                                                                                         |
| -------------------------------- | -------------------------------- | ---------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `azure.eventhub.name`            | `AZURE_EVENTHUB_NAME`            |                  | Name of the Hub, if not empty, EventHub is **enabled**                                                                              |
| `azure.eventhub.namespace`       | `AZURE_EVENTHUB_NAMESPACE`       |                  | Name of the space the Hub is in                                                                                                     |
| `azure.eventhub.minimumpriority` | `AZURE_EVENTHUB_MINIMUMPRIORITY` | `""` (= `debug`) | Minimum priority of event for using this output, order is `emergency,alert,critical,error,warning,notice,informational,debug or ""` |

> [!NOTE]
The Env var values override the settings from yaml file.

## Example of config.yaml

```yaml
azure:
  eventhub:
    name: "" # Name of the Hub, if not empty, EventHub is enabled
    namespace: "" # Name of the space the Hub is in
    # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
```

## Additional info

## Screenshots
