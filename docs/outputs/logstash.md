# Logstash

- **Category**: Logs
- **Website**: https://github.com/elastic/logstash

## Table of content

- [Logstash](#logstash)
  - [Table of content](#table-of-content)
  - [Configuration](#configuration)
  - [Example of config.yaml](#example-of-configyaml)
  - [Additional info](#additional-info)
  - [Screenshots](#screenshots)

## Configuration

| Setting                    | Env var                    | Default value    | Description                                                                                                                         |
| -------------------------- | -------------------------- | ---------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `logstash.address`         | `LOGSTASH_ADDRESS`         |                  | Logstash address, if not empty, Logstash output is **enabled**                                                                      |
| `logstash.port`            | `LOGSTASH_PORT`            | 5044             | Logstash port number                                                                                                                |
| `logstash.tls`             | `LOGSTASH_TLS`             | false            | Use TLS connection (true/false)                                                                                                     |
| `logstash.mutualtls`       | `LOGSTASH_MUTUALTLS`       | false            | Authenticate to the output with TLS; if true, checkcert flag will be ignored (server cert will always be checked)                   |
| `logstash.checkcert`       | `LOGSTASH_CHECKCERT`       | true             | Check if ssl certificate of the output is valid                                                                                     |
| `logstash.certfile`        | `LOGSTASH_CERTFILE`        |                  | Use this certificate file instead of the client certificate when using mutual TLS                                                   |
| `logstash.keyfile`         | `LOGSTASH_KEYFILE`         |                  | Use this key file instead of the client certificate when using mutual TLS                                                           |
| `logstash.cacertfile`      | `LOGSTASH_CACERTFILE`      |                  | Use this CA certificate file instead of the client certificate when using mutual TLS                                                |
| `logstash.minimumpriority` | `LOGSTASH_MINIMUMPRIORITY` | `""` (= `debug`) | Minimum priority of event for using this output, order is `emergency,alert,critical,error,warning,notice,informational,debug or ""` |
| `logstash.tags`            | `LOGSTASH_TAGS`            |                  | An additional list of tags that will be added to those produced by Falco; these tags may help in decision-making while routing logs |

> [!NOTE]
Values stored in environment variables will override the settings from yaml file.

## Example of config.yaml

```yaml
logstash:
  address: "" # Logstash address, if not empty, Logstash output is enabled
  # port: 5044 # Logstash port number (default: 5044)
  # tls: false # communicate over tls; requires Logstash version 8+ to work 
  # mutualtls: false # or authenticate to the output with TLS; if true, checkcert flag will be ignored (server cert will always be checked) (default: false)
  # checkcert: true # Check if ssl certificate of the output is valid (default: true)
  # certfile: "" # Use this certificate file instead of the client certificate when using mutual TLS (default: "")
  # keyfile: "" # Use this key file instead of the client certificate when using mutual TLS (default: "")
  # cacertfile: "" # Use this CA certificate file instead of the client certificate when using mutual TLS (default: "")
  # minimumpriority: minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default: "debug")
  # tags: ["falco"] # An additional list of tags that will be added to those produced by Falco (default: [])
```

## Additional info

## Screenshots
