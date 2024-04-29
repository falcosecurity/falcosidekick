# STAN

- **Category**: Message queue / Streaming
- **Website**: https://docs.nats.io/nats-streaming-concepts/intro

## Table of content

- [STAN](#stan)
  - [Table of content](#table-of-content)
  - [Configuration](#configuration)
  - [Example of config.yaml](#example-of-configyaml)
  - [Additional info](#additional-info)
  - [Screenshots](#screenshots)

## Configuration

| Setting                | Env var                | Default value    | Description                                                                                                                         |
| ---------------------- | ---------------------- | ---------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `stan.hostport`        | `STAN_HOSTPORT`        |                  | stan://{domain or ip}:{port}, if not empty, STAN output is **enabled**                                                              |
| `stan.clusterid`       | `STAN_CLUSTERID`       |                  | Cluster name (mandatory)                                                                                                            |
| `stan.clientid`        | `STAN_CLIENTID`        |                  | Client ID (mandatory)                                                                                                               |
| `stan.checkcert`       | `STAN_CHECKCERT`       | `true`           | Check if ssl certificate of the output is valid                                                                                     |
| `stan.minimumpriority` | `STAN_MINIMUMPRIORITY` | `""` (= `debug`) | Minimum priority of event for using this output, order is `emergency,alert,critical,error,warning,notice,informational,debug or ""` |

> [!NOTE]
The Env var values override the settings from yaml file.

## Example of config.yaml

```yaml
stan:
  hostport: "" # stan://{domain or ip}:{port}, if not empty, STAN output is enabled
  clusterid: "" # Cluster name (mandatory)
  clientid: "" # Client ID (mandatory)
  # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
  # mutualtls: false # if true, checkcert flag will be ignored (server cert will always be checked)
  # checkcert: true # check if ssl certificate of the output is valid (default: true)
```

## Additional info

## Screenshots
