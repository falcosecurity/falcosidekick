# Datadog

- **Category**: Observability
- **Website**: https://www.datadoghq.com/

## Table of content

- [Datadog](#datadog)
  - [Table of content](#table-of-content)
  - [Configuration](#configuration)
  - [Example of config.yaml](#example-of-configyaml)
  - [Additional info](#additional-info)
  - [Screenshots](#screenshots)

## Configuration

| Setting                   | Env var                   | Default value               | Description                                                                                                                         |
| ------------------------- | ------------------------- | --------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `datadog.apikey`          | `DATADOG_APIKEY`          |                             | Datadog API Key, if not empty, Datadog output is **enabled**                                                                        |
| `datadog.host`            | `DATADOG_HOST`            | `https://api.datadoghq.com` | Datadog host. Override if you are on the Datadog EU site                                                                            |
| `datadog.minimumpriority` | `DATADOG_MINIMUMPRIORITY` | `""` (= `debug`)            | Minimum priority of event for using this output, order is `emergency,alert,critical,error,warning,notice,informational,debug or ""` |

> [!NOTE]
The Env var values override the settings from yaml file.

## Example of config.yaml

```yaml
datadog:
  apikey: "" # Datadog API Key, if not empty, Datadog output is enabled
  # host: "" # Datadog host. Override if you are on the Datadog EU site. Defaults to american site with "https://api.datadoghq.com"
  # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
```

## Additional info

Filter the events in the UI with `sources: falco`.

## Screenshots

![datadog example](mages/datadog.png)