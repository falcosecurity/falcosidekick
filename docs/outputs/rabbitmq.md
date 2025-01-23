# RabbitMQ

- **Category**: Message queue / Streaming
- **Website**: https://www.rabbitmq.com/

## Table of content

- [RabbitMQ](#rabbitmq)
  - [Table of content](#table-of-content)
  - [Configuration](#configuration)
  - [Example of config.yaml](#example-of-configyaml)
  - [Additional info](#additional-info)
  - [Screenshots](#screenshots)

## Configuration

| Setting                    | Env var                    | Default value    | Description                                                                                                                         |
| -------------------------- | -------------------------- | ---------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `rabbitmq.url`             | `RABBITMQ_URL`             |                  | Rabbitmq URL, if not empty, Rabbitmq output is **enabled**                                                                          |
| `rabbitmq.queue`           | `RABBITMQ_QUEUE`           |                  | Rabbitmq Queue name                                                                                                                 |
| `rabbitmq.minimumpriority` | `RABBITMQ_MINIMUMPRIORITY` | `""` (= `debug`) | Minimum priority of event for using this output, order is `emergency,alert,critical,error,warning,notice,informational,debug or ""` |

> [!NOTE]
The Env var values override the settings from yaml file.

## Example of config.yaml

```yaml
rabbitmq:
  url: "" # Rabbitmq URL, if not empty, Rabbitmq output is enabled
  queue: "" # Rabbitmq Queue name
  # minimumpriority: "debug" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
```

## Additional info

## Screenshots
