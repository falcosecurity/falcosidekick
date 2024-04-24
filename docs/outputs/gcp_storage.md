# GCP Storage

- **Category**: Object storage
- **Website**: https://cloud.google.com/storage

## Table of content

- [GCP Storage](#gcp-storage)
  - [Table of content](#table-of-content)
  - [Configuration](#configuration)
  - [Example of config.yaml](#example-of-configyaml)
  - [Additional info](#additional-info)
  - [Screenshots](#screenshots)

## Configuration

| Setting                       | Env var                       | Default value    | Description                                                                                                                         |
| ----------------------------- | ----------------------------- | ---------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `gcp.credentials`             | `GCP_CREDENTIALS`             |                  | The base64-encoded JSON key file for the GCP service account                                                                        |
| `gcp.storage.bucket`          | `GCP_STORAGE_BUCKET`          |                  | The name of the bucket, if not empty, GCP Storage is **enabled**                                                                    |
| `gcp.storage.prefix`          | `GCP_STORAGE_PREFIX`          |                  | Prefix, keys will have format: gs://<bucket>/<prefix>/YYYY-MM-DD/YYYY-MM-DDTHH:mm:ss.s+01:00.json                                   |
| `gcp.storage.minimumpriority` | `GCP_STORAGE_MINIMUMPRIORITY` | `""` (= `debug`) | Minimum priority of event for using this output, order is `emergency,alert,critical,error,warning,notice,informational,debug or ""` |

> [!NOTE]
The Env var values override the settings from yaml file.

## Example of config.yaml

```yaml
gcp:
  credentials: "" # The base64-encoded JSON key file for the GCP service account
  storage:
    bucket: "" # The name of the bucket, if not empty, GCP Storage is enabled
    prefix : "" # Prefix, keys will have format: gs://<bucket>/<prefix>/YYYY-MM-DD/YYYY-MM-DDTHH:mm:ss.s+01:00.json
    # minimumpriority: "debug" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
```

## Additional info

## Screenshots
