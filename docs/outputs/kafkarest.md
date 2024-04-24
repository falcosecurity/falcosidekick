# Kafka Rest

- **Category**: Message queue / Streaming
- **Website**: https://docs.confluent.io/platform/current/kafka-rest/index.html

## Table of content

- [Kafka Rest](#kafka-rest)
  - [Table of content](#table-of-content)
  - [Configuration](#configuration)
  - [Example of config.yaml](#example-of-configyaml)
  - [Additional info](#additional-info)
  - [Screenshots](#screenshots)

## Configuration

| Setting                     | Env var                     | Default value    | Description                                                                                                                         |
| --------------------------- | --------------------------- | ---------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `kafkarest.address`         | `KAFKAREST_ADDRESS`         |                  | The full URL to the topic (example "http://kafkarest:8082/topics/test"), if not empty, Kafka Rest is **enabled**                    |
| `kafkarest.version`         | `KAFKAREST_VERSION`         | `2`              | Kafka Rest Proxy API version `2` or `1`                                                                                             |
| `kafkarest.mutualtls`       | `KAFKAREST_MUTUALTLS`       | `false`          | Authenticate to the output with TLS, if true, checkcert flag will be ignored (server cert will always be checked)                   |
| `kafkarest.checkcert`       | `KAFKAREST_CHECKCERT`       | `true` | Check if ssl certificate of the output is valid                                                                                     |
| `kafkarest.minimumpriority` | `KAFKAREST_MINIMUMPRIORITY` | `""` (= `debug`) | Minimum priority of event for using this output, order is `emergency,alert,critical,error,warning,notice,informational,debug or ""` |

> [!NOTE]
The Env var values override the settings from yaml file.

## Example of config.yaml

```yaml
kafkarest:
  address: "" # The full URL to the topic (example "http://kafkarest:8082/topics/test")
  # version: 2 # Kafka Rest Proxy API version 2|1 (default: 2)
  # mutualtls: false # if true, checkcert flag will be ignored (server cert will always be checked)
  # checkcert: true # check if ssl certificate of the output is valid (default: true)
  # minimumpriority: "debug" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
```

## Additional info

## Screenshots
