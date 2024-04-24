# Webhook

- **Category**: Web
- **Website**: <n/a>

## Table of content

- [Webhook](#webhook)
  - [Table of content](#table-of-content)
  - [Configuration](#configuration)
  - [Example of config.yaml](#example-of-configyaml)
  - [Additional info](#additional-info)
  - [Screenshots](#screenshots)

## Configuration

| Setting                   | Env var                   | Default value    | Description                                                                                                                         |
| ------------------------- | ------------------------- | ---------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `webhook.address`         | `WEBHOOK_ADDRESS`         |                  | Webhook address, if not empty, Webhook output is **enabled**                                                                        |
| `webhook.method`          | `WEBHOOK_METHOD`          | `POST`           | Webhook http method: `POST` or `PUT`                                                                                                |
| `webhook.customheaders`   | `WEBHOOK_CUSTOMHEADERS`   |                  | Custom headers to add in POST, useful for Authentication                                                                            |
| `webhook.mutualtls`       | `WEBHOOK_MUTUALTLS`       | `false`          | Authenticate to the output with TLS, if true, checkcert flag will be ignored (server cert will always be checked)                   |
| `webhook.checkcert`       | `WEBHOOK_CHECKCERT`       | `true`           | Check if ssl certificate of the output is valid                                                                                     |
| `webhook.minimumpriority` | `WEBHOOK_MINIMUMPRIORITY` | `""` (= `debug`) | Minimum priority of event for using this output, order is `emergency,alert,critical,error,warning,notice,informational,debug or ""` |

> [!NOTE]
The Env var values override the settings from yaml file.

## Example of config.yaml

```yaml
webhook:
  address: "" # Webhook address, if not empty, Webhook output is enabled
  # method: "POST" # Webhook http method: POST or PUT (default: POST)
  # customHeaders: # Custom headers to add in the request, useful for Authentication
  #   key: value
  # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
  # mutualtls: false # if true, checkcert flag will be ignored (server cert will always be checked)
  # checkcert: true # check if ssl certificate of the output is valid (default: true)
```

## Additional info

## Screenshots
