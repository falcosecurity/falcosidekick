# Cloud Events

- **Category**: FaaS / Serverless
- **Website**: https://cloudevents.io/

## Table of content

- [Cloud Events](#cloud-events)
  - [Table of content](#table-of-content)
  - [Configuration](#configuration)
  - [Example of config.yaml](#example-of-configyaml)
  - [Additional info](#additional-info)
  - [Screenshots](#screenshots)

## Configuration

| Setting                       | Env var                       | Default value    | Description                                                                                                                         |
| ----------------------------- | ----------------------------- | ---------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `cloudevents.address`         | `CLOUDEVENTS_ADDRESS`         |                  | CloudEvents consumer http address, if not empty, CloudEvents output is **enabled**                                                  |
| `cloudevents.extensions`      | `CLOUDEVENTS_EXTENSIONS`      |                  | Extensions to add in the outbound Event, useful for routing                                                                         |
| `cloudevents.mutualtls`       | `CLOUDEVENTS_MUTUALTLS`       | `false`          | Authenticate to the output with TLS, if true, checkcert flag will be ignored (server cert will always be checked)                   |
| `cloudevents.checkcert`       | `CLOUDEVENTS_CHECKCERT`       | `true` | Check if ssl certificate of the output is valid                                                                                     |
| `cloudevents.minimumpriority` | `CLOUDEVENTS_MINIMUMPRIORITY` | `""` (= `debug`) | Minimum priority of event for using this output, order is `emergency,alert,critical,error,warning,notice,informational,debug or ""` |

> [!NOTE]
The Env var values override the settings from yaml file.

## Example of config.yaml

```yaml
cloudevents:
  address: "" # CloudEvents consumer http address, if not empty, CloudEvents output is enabled
  # extensions: # Extensions to add in the outbound Event, useful for routing
  #   key: value
  # mutualtls: false # if true, checkcert flag will be ignored (server cert will always be checked)
  # checkcert: true # check if ssl certificate of the output is valid (default: true)
  # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)

```

## Additional info

> [!NOTE]
This output works with [`KNative`](https://knative.dev/).

## Screenshots


