# Yandex Datastreams

- **Category**: Message queue / Streaming
- **Website**: https://cloud.yandex.com/en/docs/data-streams/

## Table of content

- [Yandex Datastreams](#yandex-datastreams)
  - [Table of content](#table-of-content)
  - [Configuration](#configuration)
  - [Example of config.yaml](#example-of-configyaml)
  - [Additional info](#additional-info)
  - [Screenshots](#screenshots)

## Configuration

| Setting                              | Env var                              | Default value                            | Description                                                                                                                         |
| ------------------------------------ | ------------------------------------ | ---------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `yandex.accesskeyid`                 | `YANDEX_ACCESSKEYID`                 |                                          | Yandex access key                                                                                                                   |
| `yandex.secretaccesskey`             | `YANDEX_SECRETACCESSKEY`             |                                          | Yandex secret access key                                                                                                            |
| `yandex.region`                      | `YANDEX_REGION`                      | `ru-central-1`                          | Yandex region                                                                                                                       |
| `yandex.datastreams.endpoint`        | `YANDEX_DATASTREAMS_ENDPOINT`        | `https://yds.serverless.yandexcloud.net` | Yandex Data Streams endpoint                                                                                                        |
| `yandex.datastreams.streamname`      | `YANDEX_DATASTREAMS_STREAMNAME`      |                                          | Stream name in format `/${region}/${folder_id}/${ydb_id}/${stream_name}`, if not empty, Yandex Datastreams is **enabled**                                                           |
| `yandex.datastreams.minimumpriority` | `YANDEX_DATASTREAMS_MINIMUMPRIORITY` | `""` (= `debug`)                         | Minimum priority of event for using this output, order is `emergency,alert,critical,error,warning,notice,informational,debug or ""` |

> [!NOTE]
The Env var values override the settings from yaml file.

## Example of config.yaml

```yaml
yandex:
  # accesskeyid: "" # Yandex access key
  # secretaccesskey: "" # Yandex secret access key
  # region: "" # Yandex storage region (default: ru-central-1)
  datastreams:
    # endpoint: "" # Yandex Data Streams endpoint (default: https://yds.serverless.yandexcloud.net)
    streamname: "" # Stream name in format /${region}/${folder_id}/${ydb_id}/${stream_name}, if not empty, Yandex Datastreams is enabled
    # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug
```

## Additional info

## Screenshots
