# Yandex S3

- **Category**: Object storage
- **Website**: https://cloud.yandex.com/en-ru/services/storage

## Table of content

- [Yandex S3](#yandex-s3)
  - [Table of content](#table-of-content)
  - [Configuration](#configuration)
  - [Example of config.yaml](#example-of-configyaml)
  - [Additional info](#additional-info)
  - [Screenshots](#screenshots)

## Configuration

| Setting                     | Env var                     | Default value    | Description                                                                                                                         |
| --------------------------- | --------------------------- | ---------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `yandex.accesskeyid`        | `YANDEX_ACCESSKEYID`        |                  | Yandex access key                                                                                                                   |
| `yandex.secretaccesskey`    | `YANDEX_SECRETACCESSKEY`    |                  | Yandex secret access Key                                                                                                            |
| `yandex.region`             | `YANDEX_REGION`             | `ru-central-1`  | Yandex region                                                                                                                       |
| `yandex.s3.bucket`          | `YANDEX_S3_BUCKET`          |                  | Yandex storage, bucket name, if not empty, Yandex Storage is **enabled**                                                            |
| `yandex.s3.endpoint`        | `YANDEX_S3_ENDPOINT`        |                  | Yandex storage endpoint                                                                                                             |
| `yandex.s3.prefix`          | `YANDEX_S3_PREFIX`          |                  | Prefix, keys will have format: s3://<bucket>/<prefix>/YYYY-MM-DD/YYYY-MM-DDTHH:mm:ss.s+01:00.json                                   |
| `yandex.s3.minimumpriority` | `YANDEX_S3_MINIMUMPRIORITY` | `""` (= `debug`) | Minimum priority of event for using this output, order is `emergency,alert,critical,error,warning,notice,informational,debug or ""` |

> [!NOTE]
The Env var values override the settings from yaml file.

## Example of config.yaml

```yaml
yandex:
  # accesskeyid: "" # Yandex access key
  # secretaccesskey: "" # Yandex secret access key
  # region: "" # Yandex region (default: ru-central-1)
  s3:
    bucket: "" # Yandex storage, bucket name, if not empty, Yandex Storage is enabled
    # endpoint: "" # Yandex storage endpoint (default: https://storage.yandexcloud.net)
    # prefix: "" # Prefix, keys will have format: s3://<bucket>/<prefix>/YYYY-MM-DD/YYYY-MM-DDTHH:mm:ss.s+01:00.json
    # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug
```

## Additional info

## Screenshots
