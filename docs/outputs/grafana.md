# Grafana

- **Category**: Logs
- **Website**: https://grafana.com/

## Table of content

- [Grafana](#grafana)
  - [Table of content](#table-of-content)
  - [Configuration](#configuration)
  - [Example of config.yaml](#example-of-configyaml)
  - [Additional info](#additional-info)
  - [Screenshots](#screenshots)

## Configuration

| Setting                   | Env var                   | Default value    | Description                                                                                                                         |
| ------------------------- | ------------------------- | ---------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `grafana.hostport`        | `GRAFANA_HOSTPORT`        |                  | http://{domain or ip}:{port}, if not empty, Grafana output is **enabled**                                                           |
| `grafana.apikey`          | `GRAFANA_HOSTPORT`        |                  | API Key to authenticate to Grafana                                                                                                  |
| `grafana.dashboardid`     | `GRAFANA_DASHBOARDID`     |                  | Annotations are scoped to a specific dashboard. Optionnal.                                                                          |
| `grafana.panelid`         | `GRAFANA_PANELID`         |                  | Annotations are scoped to a specific panel. Optionnal.                                                                              |
| `grafana.allfieldsastags` | `GRAFANA_ALLFIELDSASTAGS` | `false`          | If true, all custom fields are added as tags                                                                                        |
| `grafana.customheaders`   | `GRAFANA_CUSTOMHEADERS`   |                  | Custom headers for the POST request                                                                                                 |
| `grafana.checkcert`       | `GRAFANA_CHECKCERT`       | `true` | Check if ssl certificate of the output is valid                                                                                     |
| `grafana.minimumpriority` | `GRAFANA_MINIMUMPRIORITY` | `""` (= `debug`) | Minimum priority of event for using this output, order is `emergency,alert,critical,error,warning,notice,informational,debug or ""` |

> [!NOTE]
The Env var values override the settings from yaml file.

## Example of config.yaml

```yaml
grafana:
  hostport: "" # http://{domain or ip}:{port}, if not empty, Grafana output is enabled
  apikey: "" # API Key to authenticate to Grafana, if not empty, Grafana output is enabled
  # dashboardid: "" # annotations are scoped to a specific dashboard. Optionnal.
  # panelid: "" # annotations are scoped to a specific panel. Optionnal.
  # allfieldsastags: false # if true, all custom fields are added as tags (default: false)
  # customHeaders: # Custom headers to add in POST, useful for Authentication
  #   key: value
  # mutualtls: false # if true, checkcert flag will be ignored (server cert will always be checked)
  # checkcert: true # check if ssl certificate of the output is valid (default: true)
  # minimumpriority: "debug" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
```

## Additional info

> [!NOTE]
This output creates annotations.

## Screenshots
