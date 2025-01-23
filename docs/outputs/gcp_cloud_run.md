# GCP Cloud Run

- **Category**: Faas / Serverless
- **Website**: https://cloud.google.com/run

## Table of content

- [GCP Cloud Run](#gcp-cloud-run)
  - [Table of content](#table-of-content)
  - [Configuration](#configuration)
  - [Example of config.yaml](#example-of-configyaml)
  - [Additional info](#additional-info)
  - [Screenshots](#screenshots)

## Configuration

| Setting                        | Env var                        | Default value    | Description                                                                                                                         |
| ------------------------------ | ------------------------------ | ---------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `gcp.credentials`              | `GCP_CREDENTIALS`              |                  | The base64-encoded JSON key file for the GCP service account                                                                        |
| `gcp.cloudrun.endpoint`        | `GCP_CLOUDRUN_ENDPOINT`        |                  | The URL of the Cloud Run, if not empty, Google Cloud Run is **enabled**                                                             |
| `gcp.cloudrun.jwt`             | `GCP_CLOUDRUN_JWT`             |                  | Appropriate JWT to invoke the Cloud Function                                                                                        |
| `gcp.cloudrun.minimumpriority` | `GCP_CLOUDRUN_MINIMUMPRIORITY` | `""` (= `debug`) | Minimum priority of event for using this output, order is `emergency,alert,critical,error,warning,notice,informational,debug or ""` |

> [!NOTE]
The Env var values override the settings from yaml file.

## Example of config.yaml

```yaml
gcp:
  credentials: "" # The base64-encoded JSON key file for the GCP service account
  cloudrun:
    endpoint: "" # The URL of the Cloud Function
    jwt: "" # Appropriate JWT to invoke the Cloud Function
    # minimumpriority: "debug" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
```

## Additional info

## Screenshots
