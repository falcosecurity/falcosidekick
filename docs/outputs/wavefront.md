# Wavefront

- **Category**: Metrics / Observability
- **Website**: https://www.wavefront.com/

## Table of content

- [Wavefront](#wavefront)
  - [Table of content](#table-of-content)
  - [Configuration](#configuration)
  - [Example of config.yaml](#example-of-configyaml)
  - [Additional info](#additional-info)
  - [Screenshots](#screenshots)

## Configuration

| Setting                          | Env var                          | Default value    | Description                                                                                                                         |
| -------------------------------- | -------------------------------- | ---------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `wavefront.endpointhost`         | `WAVEFRONT_ENDPOINTHOST`         |                  | Wavefront endpoint address (only the host). If not empty, with endpointhost, Wavefront output is **enabled**                        |
| `wavefront.endpointtype`         | `WAVEFRONT_ENDPOINTTYPE`         | `direct`         | Wavefront endpoint type, must be `direct` or `proxy`                                                                                |
| `wavefront.endpointmetricport`   | `WAVEFRONT_ENDPOINTMETRICPORT`   | `2878`           | Wavefront endpoint port when type is `proxy`                                                                                        |
| `wavefront.endpointtoken`        | `WAVEFRONT_ENDPOINTTOKEN`        |                  | Wavefront token. Must be used only when endpointtype is `direct`                                                                    |
| `wavefront.metricname`           | `WAVEFRONT_METRICNAME`           | `falco.alert`    | Metric to be created in Wavefront                                                                                                   |
| `wavefront.batchsize`            | `WAVEFRONT_BATCHSIZE`            | `10000`          | Max batch of data sent per flush interval. Used only in `direct` mode                                                               |
| `wavefront.flushintervalseconds` | `WAVEFRONT_FLUSHINTERVALSECONDS` | `1`              | Time in seconds between flushing metrics to Wavefront                                                                               |
| `wavefront.minimumpriority`      | `WAVEFRONT_MINIMUMPRIORITY`      | `""` (= `debug`) | Minimum priority of event for using this output, order is `emergency,alert,critical,error,warning,notice,informational,debug or ""` |

> [!NOTE]
The Env var values override the settings from yaml file.

## Example of config.yaml

```yaml
wavefront:
  endpointhost: "" # Wavefront endpoint address (only the host). If not empty, with endpointhost, Wavefront output is enabled
  endpointtype: "direct" # Wavefront endpoint type, must be 'direct' or 'proxy'
  # endpointmetricport: 2878 # Wavefront endpoint port when type is 'proxy'
  # endpointtoken: "" # Wavefront token. Must be used only when endpointtype is 'direct'
  # metricname: "falco.alert" # Metric to be created in Wavefront. Defaults to falco.alert
  # batchsize: 10000 # Max batch of data sent per flush interval. defaults to 10,000. Used only in direct mode
  # flushintervalseconds: 1 # Time in seconds between flushing metrics to Wavefront. Defaults to 1s
  # minimumpriority: "debug" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
```

## Additional info

## Screenshots
