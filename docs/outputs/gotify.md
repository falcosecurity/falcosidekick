# Gotify

- **Category**: Message queue / Streaming
- **Website**: https://gotify.net/

## Table of content

- [Gotify](#gotify)
  - [Table of content](#table-of-content)
  - [Configuration](#configuration)
  - [Example of config.yaml](#example-of-configyaml)
  - [Additional info](#additional-info)
  - [Screenshots](#screenshots)

## Configuration

| Setting                  | Env var                  | Default value    | Description                                                                                                                         |
| ------------------------ | ------------------------ | ---------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `gotify.hostport`        | `GOTIFY_HOSTPORT`        |                  | http://{domain or ip}:{port}, if not empty, Gotify output is **enabled**                                                            |
| `gotify.token`           | `GOTIFY_TOKEN`           |                  | API Token                                                                                                                           |
| `gotify.format`          | `GOTIFY_FORMAT`          | `markdown`       | Format of the messages (`plaintext`, `markdown`, `json`)                                                                            |
| `gotify.checkcert`       | `GOTIFY_CHECKCERT`       | `true` | Check if ssl certificate of the output is valid                                                                                     |
| `gotify.minimumpriority` | `GOTIFY_MINIMUMPRIORITY` | `""` (= `debug`) | Minimum priority of event for using this output, order is `emergency,alert,critical,error,warning,notice,informational,debug or ""` |

> [!NOTE]
The Env var values override the settings from yaml file.

## Example of config.yaml

```yaml
gotify:
  hostport: "" # http://{domain or ip}:{port}, if not empty, Gotify output is enabled
  token: "" # API Token
  # format: "markdown" # Format of the messages (plaintext, markdown, json) (default: markdown)
  # checkcert: true # check if ssl certificate of the output is valid (default: true)
  # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
```

## Additional info

## Screenshots

![gotify example](images/gotify.jpg)