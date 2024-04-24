# PagerDuty

- **Category**: Alerting
- **Website**: https://pagerduty.com/

## Table of content

- [PagerDuty](#pagerduty)
  - [Table of content](#table-of-content)
  - [Configuration](#configuration)
  - [Example of config.yaml](#example-of-configyaml)
  - [Additional info](#additional-info)
  - [Screenshots](#screenshots)

## Configuration

| Setting                     | Env var                     | Default value    | Description                                                                                                                         |
| --------------------------- | --------------------------- | ---------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `pagerduty.routingkey`      | `PAGERDUTY_ROUTINGKEY`          |                  | Pagerduty Routing Key, if not empty, Pagerduty output is **enabled**                                                                |
| `pagerduty.region`          | `PAGERDUTY_REGION`          | `us`             | Pagerduty Region (`us`, `eu`)                                                                                                       |
| `pagerduty.minimumpriority` | `PAGERDUTY_MINIMUMPRIORITY` | `""` (= `debug`) | Minimum priority of event for using this output, order is `emergency,alert,critical,error,warning,notice,informational,debug or ""` |

> [!NOTE]
The Env var values override the settings from yaml file.

## Example of config.yaml

```yaml
pagerduty:
  routingkey: "" # Pagerduty Routing Key, if not empty, Pagerduty output is enabled
  region: "us" # Pagerduty Region, can be 'us' or 'eu' (default: us)
  minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
```

## Additional info

## Screenshots
