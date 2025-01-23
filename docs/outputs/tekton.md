# Tekton

- **Category**: Category of the output
- **Website**: URL of the output

## Table of content

- [Tekton](#tekton)
  - [Table of content](#table-of-content)
  - [Configuration](#configuration)
  - [Example of config.yaml](#example-of-configyaml)
  - [Additional info](#additional-info)
  - [Screenshots](#screenshots)

## Configuration

| Setting                  | Env var                  | Default value    | Description                                                                                                                         |
| ------------------------ | ------------------------ | ---------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `tekton.eventListener`   | `TEKTON_EVENTLISTENER`   |                  | EventListener address, if not empty, Tekton output is **enabled**                                                                   |
| `tekton.mutualtls`       | `TEKTON_MUTUALTLS`       | `false`          | Authenticate to the output with TLS, if true, checkcert flag will be ignored (server cert will always be checked)                   |
| `tekton.checkcert`       | `TEKTON_CHECKCERT`       | `true`           | Check if ssl certificate of the output is valid                                                                                     |
| `tekton.minimumpriority` | `TEKTON_MINIMUMPRIORITY` | `""` (= `debug`) | Minimum priority of event for using this output, order is `emergency,alert,critical,error,warning,notice,informational,debug or ""` |

> [!NOTE]
The Env var values override the settings from yaml file.

## Example of config.yaml

```yaml
tekton:
  eventlistener: "" # EventListener address, if not empty, Tekton output is enabled
  # mutualtls: false # if true, checkcert flag will be ignored (server cert will always be checked)
  # checkcert: true # check if ssl certificate of the output is valid (default: true)
  # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
```

## Additional info

## Screenshots
