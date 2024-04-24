# Kafka

- **Category**: Message queue / Streaming
- **Website**: https://kafka.apache.org/

## Table of content

- [Kafka](#kafka)
  - [Table of content](#table-of-content)
  - [Configuration](#configuration)
  - [Example of config.yaml](#example-of-configyaml)
  - [Additional info](#additional-info)
  - [Screenshots](#screenshots)

## Configuration

| Setting                 | Env var                 | Default value    | Description                                                                                                                                                                                                                                                |
| ----------------------- | ----------------------- | ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `kafka.hostport`        | `KAFKA_HOSTPORT`        |                  | Comma separated list of Apache Kafka bootstrap nodes for establishing the initial connection to the cluster (ex: localhost:9092,localhost:9093). Defaults to port 9092 if no port is specified after the domain, if not empty, Kafka output is **enabled** |
| `kafka.topic`           | `KAFKA_TOPIC`           |                  | Name of the topic                                                                                                                                                                                                                                          |
| `kafka.topiccreation`   | `KAFKA_TOPICCREATION`   | `false`          | Auto create the topic if it doesn't exist                                                                                                                                                                                                                  |
| `kafka.sasl`            | `KAFKA_SASL`            |                  | SASL authentication mechanism, if empty, no authentication (`PLAIN`, `SCRAM_SHA256`, `SCRAM_SHA512`)                                                                                                                                                       |
| `kafka.tls`             | `KAFKA_TSL`             | `false`          | Use TLS for the connections                                                                                                                                                                                                                                |
| `kafka.username`        | `KAFKA_USERNAME`        |                  | Use this username to authenticate to Kafka via SASL                                                                                                                                                                                                        |
| `kafka.password`        | `KAFKA_PASSWORD`        |                  | Use this password to authenticate to Kafka via SASL                                                                                                                                                                                                        |
| `kafka.async`           | `KAFKA_ASYNC`           | `false`          | Produce messages without blocking                                                                                                                                                                                                                          |
| `kafka.requiredacks`    | `KAFKA_REQUIREDACKS`    | `NONE`           | Number of acknowledges from partition replicas required before receiving                                                                                                                                                                                   |
| `kafka.compression`     | `KAFKA_COMPRESSION`     | `NONE`           | Enable message compression using this algorithm (`GZIP`, `SNAPPY`, `LZ4`, `ZSTD`, `NONE`)                                                                                                                                                                  |
| `kafka.balancer`        | `KAFKA_BALANCER`        | `round_robin`    | Partition balancing strategy when producing                                                                                                                                                                                                                |
| `kafka.clientid`        | `KAFKA_CLIENTID`        |                  | Specify a client.id when communicating with the broker for tracing                                                                                                                                                                                         |
| `kafka.minimumpriority` | `KAFKA_MINIMUMPRIORITY` | `""` (= `debug`) | Minimum priority of event for using this output, order is `emergency,alert,critical,error,warning,notice,informational,debug or ""`                                                                                                                        |

> [!NOTE]
The Env var values override the settings from yaml file.

## Example of config.yaml

```yaml
kafka:
  hostport: "" # Comma separated list of Apache Kafka bootstrap nodes for establishing the initial connection to the cluster (ex: localhost:9092,localhost:9093). Defaults to port 9092 if no port is specified after the domain, if not empty, Kafka output is enabled
  topic: "" # Name of the topic
  # topiccreation: false # auto create the topic if it doesn't exist (default: false)
  # sasl: "" # SASL authentication mechanism, if empty, no authentication (PLAIN|SCRAM_SHA256|SCRAM_SHA512)
  # tls: false # Use TLS for the connections (default: false)
  # username: "" # use this username to authenticate to Kafka via SASL (default: "")
  # password: "" # use this password to authenticate to Kafka via SASL (default: "")
  # async: false # produce messages without blocking (default: false)
  # requiredacks: NONE # number of acknowledges from partition replicas required before receiving (default: "NONE")
  # compression: "" # enable message compression using this algorithm (GZIP|SNAPPY|LZ4|ZSTD|NONE) (default: "NONE")
  # balancer: "" # partition balancing strategy when producing (default: "round_robin")
  # clientid: "" # specify a client.id when communicating with the broker for tracing
  # minimumpriority: "debug" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
```

## Additional info

## Screenshots
