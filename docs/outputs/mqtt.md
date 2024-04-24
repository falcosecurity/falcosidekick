# MQTT

- **Category**: Message queue / Streaming
- **Website**: https://mqtt.org/

## Table of content

- [MQTT](#mqtt)
  - [Table of content](#table-of-content)
  - [Configuration](#configuration)
  - [Example of config.yaml](#example-of-configyaml)
  - [Additional info](#additional-info)
  - [Screenshots](#screenshots)

## Configuration

| Setting                | Env var                | Default value    | Description                                                                                                                         |
| ---------------------- | ---------------------- | ---------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `mqtt.broker`          | `MQTT_BROKER`          |                  | Broker address, can start with tcp:// or ssl://, if not empty, MQTT output is **enabled**                                           |
| `mqtt.topic`           | `MQTT_TOPIC`           | `falco/events`   | Topic for messages                                                                                                                  |
| `mqtt.qos`             | `MQTT_QOS`             | `0`              | QOS for messages                                                                                                                    |
| `mqtt.retained`        | `MQTT_RETAINED`        | `false`          | If true, messages are retained                                                                                                      |
| `mqtt.user`            | `MQTT_USER`            |                  | User if the authentication is enabled in the broker                                                                                 |
| `mqtt.password`        | `MQTT_PASSWORD`        |                  | Password if the authentication is enabled in the broker                                                                             |
| `mqtt.checkcert`       | `MQTT_CHECKCERT`       | `true`           | Check if ssl certificate of the output is valid                                                                                     |
| `mqtt.minimumpriority` | `MQTT_MINIMUMPRIORITY` | `""` (= `debug`) | Minimum priority of event for using this output, order is `emergency,alert,critical,error,warning,notice,informational,debug or ""` |

> [!NOTE]
The Env var values override the settings from yaml file.

## Example of config.yaml

```yaml
mqtt:
  broker: "" # Broker address, can start with tcp:// or ssl://, if not empty, MQTT output is enabled
  topic: "falco/events" # Topic for messages (default: falco/events)
  # qos: 0 # QOS for messages (default: 0)
  # retained: false # If true, messages are retained (default: false)
  # user: "" # User if the authentication is enabled in the broker
  # password: "" # Password if the authentication is enabled in the broker
  # checkcert: true # check if ssl certificate of the output is valid (default: true)
  # minimumpriority: "debug" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
```

## Additional info

## Screenshots
