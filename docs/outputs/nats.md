# NATS

- **Category**: Message queue / Streaming
- **Website**: https://nats.io/

## Table of content

- [NATS](#nats)
  - [Table of content](#table-of-content)
  - [Configuration](#configuration)
- [subjecttemplate: "falco.." # template for the subject, tokens  and  will be automatically replaced (default: falco..)](#subjecttemplate-falco--template-for-the-subject-tokens--and--will-be-automatically-replaced-default-falco)
  - [Example of config.yaml](#example-of-configyaml)
  - [Additional info](#additional-info)
  - [Screenshots](#screenshots)

## Configuration

  # subjecttemplate: "falco.<priority>.<rule>" # template for the subject, tokens <priority> and <rule> will be automatically replaced (default: falco.<priority>.<rule>)


|        Setting         |        Env var         |       Default value       |                                                             Description                                                             |
| ---------------------- | ---------------------- | ------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `nats.hostport`        | `NATS_HOSTPORT`        |                           | nats://{domain or ip}:{port}, if not empty, NATS output is **enabled**                                                              |
| `nats.subjecttemplate` | `NATS_SUBJECTTEMPLATE` | `falco.<priority>.<rule>` | Template for the subject, tokens <priority> and <rule> will be automatically replaced                                               |
| `nats.mutualtls`       | `NATS_MUTUALTLS`       | `false`                   | Authenticate to the output with TLS, if true, checkcert flag will be ignored (server cert will always be checked)                   |
| `nats.checkcert`       | `NATS_CHECKCERT`       | `true`                    | Check if ssl certificate of the output is valid                                                                                     |
| `nats.minimumpriority` | `NATS_MINIMUMPRIORITY` | `""` (= `debug`)          | Minimum priority of event for using this output, order is `emergency,alert,critical,error,warning,notice,informational,debug or ""` |

> [!NOTE]
The Env var values override the settings from yaml file.

## Example of config.yaml

```yaml
nats:
  hostport: "" # nats://{domain or ip}:{port}, if not empty, NATS output is enabled
  # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
  # subjecttemplate: "falco.<priority>.<rule>" # template for the subject, tokens <priority> and <rule> will be automatically replaced (default: falco.<priority>.<rule>)
  # mutualtls: false # if true, checkcert flag will be ignored (server cert will always be checked)
  # checkcert: true # check if ssl certificate of the output is valid (default: true)
```

## Additional info

## Screenshots
