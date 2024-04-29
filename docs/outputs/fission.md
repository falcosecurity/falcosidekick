# Fission

- **Category**: FaaS / Serverless
- **Website**: URL of the output

## Table of content

- [Fission](#fission)
  - [Table of content](#table-of-content)
  - [Configuration](#configuration)
  - [Example of config.yaml](#example-of-configyaml)
  - [Additional info](#additional-info)
  - [Screenshots](#screenshots)

## Configuration

| Setting                   | Env var                   | Default value    | Description                                                                                                                         |
| ------------------------- | ------------------------- | ---------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `fission.function`        | `FISSION_FUNCTION`        |                  | Name of Fission function, if not empty, Fission is **enabled**                                                                      |
| `fission.routernamespace` | `FISSION_ROUTERNAMESPACE` | `fission`        | Namespace of Fission Router                                                                                                         |
| `fission.routerservice`   | `FISSION_ROUTERSERVICE`   | `router`         | Service of Fission Router                                                                                                           |
| `fission.routerport`      | `FISSION_ROUTERPORT`      | `80`             | Port of service of Fission Router                                                                                                   |
| `fission.mutualtls`       | `FISSION_MUTUALTLS`       | `false`          | Authenticate to the output with TLS, if true, checkcert flag will be ignored (server cert will always be checked)                   |
| `fission.checkcert`       | `FISSION_CHECKCERT`       | `true` | Check if ssl certificate of the output is valid                                                                                     |
| `fission.minimumpriority` | `FISSION_MINIMUMPRIORITY` | `""` (= `debug`) | Minimum priority of event for using this output, order is `emergency,alert,critical,error,warning,notice,informational,debug or ""` |

> [!NOTE]
The Env var values override the settings from yaml file.

## Example of config.yaml

```yaml
fission:
  function: "" # Name of Fission function, if not empty, Fission is enabled
  routernamespace: "fission" # Namespace of Fission Router, "fission" (default)
  routerservice: "router" # Service of Fission Router, "router" (default)
  routerport: 80 # Port of service of Fission Router
  # minimumpriority: "debug" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
  # checkcert: true # check if ssl certificate of the output is valid (default: true)
  # mutualtls: false # if true, checkcert flag will be ignored (server cert will always be checked)

```

## Additional info

## Screenshots
