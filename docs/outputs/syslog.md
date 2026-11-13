# Syslog

- **Category**: Syslog
- **Website**: https://en.wikipedia.org/wiki/Syslog

## Table of content

- [Syslog](#syslog)
  - [Table of content](#table-of-content)
  - [Configuration](#configuration)
  - [Example of config.yaml](#example-of-configyaml)
  - [Additional info](#additional-info)
  - [Screenshots](#screenshots)

## Configuration

| Setting                  | Env var                  | Default value    | Description                                                                                                                         |
| ------------------------ | ------------------------ | ---------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `syslog.host`            | `SYSLOG_HOST`            |                  | Syslog host, if not empty, Syslog output is enabled                                                                                 |
| `syslog.port`            | `SYSLOG_PORT`            |                  | Syslog endpoint port number                                                                                                         |
| `syslog.protocol`        | `SYSLOG_PROTOCOL`        | `tcp`            | Syslog transport protocol. It can be either `tcp` or `udp`                                                                          |
| `syslog.format`          | `SYSLOG_FORMAT`          | `json`           | Syslog payload format. It can be either `json` or `cef`                                                                             |
| `syslog.tls`             | `SYSLOG_TLS`             | `false`          | Send the events over TLS (RFC 5425), requires the `tcp` protocol. The events are then sent as RFC 5424 messages with octet-counting framing |
| `syslog.checkcert`       | `SYSLOG_CHECKCERT`       | `true`           | Check if the TLS certificate of the Syslog server is valid, only used if `syslog.tls` is `true`                                     |
| `syslog.mutualtls`       | `SYSLOG_MUTUALTLS`       | `false`          | Authenticate to the Syslog server with the client certificate set in the `mutualtlsclient` settings, only used if `syslog.tls` is `true` |
| `syslog.minimumpriority` | `SYSLOG_MINIMUMPRIORITY` | `""` (= `debug`) | Minimum priority of event for using this output, order is `emergency,alert,critical,error,warning,notice,informational,debug or ""` |

> [!NOTE]
The Env var values override the settings from yaml file.

## Example of config.yaml

```yaml
syslog:
  host: "" # Syslog host, if not empty, Syslog output is enabled
  port: "" # Syslog endpoint port number
  # protocol: "" # Syslog transport protocol. It can be either "tcp" or "udp" (default: tcp)
  # format: "" # Syslog payload format. It can be either "json" or "cef" (default: json)
  # tls: false # Send the events over TLS (RFC 5425), requires the "tcp" protocol (default: false)
  # checkcert: true # check if the TLS certificate of the Syslog server is valid, only used if tls is true (default: true)
  # mutualtls: false # authenticate with the client certificate of the mutualtlsclient settings, only used if tls is true (default: false)
  # minimumpriority: "debug" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
```

## Additional info
```
# Recommended version rsyslogd  8.2102 or newer
rsyslogd -v to check the version
```
## Screenshots
