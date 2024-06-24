# Falco Talon

- **Category**: Response engine
- **Website**: https://docs.falco-talon.org

## Table of content

- [Falco Talon](#falco-talon)
  - [Table of content](#table-of-content)
  - [Configuration](#configuration)
  - [Example of config.yaml](#example-of-configyaml)
  - [Additional info](#additional-info)
  - [Screenshots](#screenshots)

## Configuration

|         Setting         |         Env var         |  Default value   |                                                             Description                                                             |
| ----------------------- | ----------------------- | ---------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `talon.address`         | `TALON_ADDRESS`         |                  | Talon address, if not empty, Talon output is **enabled**                                                                            |
| `talon.checkcert`       | `TALON_CHECKCERT`       | `true`           | Check if ssl certificate of the output is valid                                                                                     |
| `talon.minimumpriority` | `TALON_MINIMUMPRIORITY` | `""` (= `debug`) | Minimum priority of event for using this output, order is `emergency,alert,critical,error,warning,notice,informational,debug or ""` |

> [!NOTE]
The Env var values override the settings from yaml file.

## Example of config.yaml

```yaml
talon:
  address: "" # Talon address, if not empty, Talon output is enabled
  # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
  # checkcert: true # check if ssl certificate of the output is valid (default: true)
```

## Additional info

> [!WARNING]
> Falco Talon is active under development and this integration may change in the future to reflect this evolution.

## Screenshots
