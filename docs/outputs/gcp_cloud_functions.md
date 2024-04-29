# GCP Cloud Functions

- **Category**: FaaS / Serverless
- **Website**: https://cloud.google.com/functions

## Table of content

- [GCP Cloud Functions](#gcp-cloud-functions)
  - [Table of content](#table-of-content)
  - [Configuration](#configuration)
  - [Example of config.yaml](#example-of-configyaml)
  - [Additional info](#additional-info)
  - [Screenshots](#screenshots)

## Configuration

| Setting                              | Env var                              | Default value    | Description                                                                                                                         |
| ------------------------------------ | ------------------------------------ | ---------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `gcp.credentials`                    | `GCP_CREDENTIALS`                    |                  | The base64-encoded JSON key file for the GCP service account                                                                        |
| `gcp.cloudfunctions.name`            | `GCP_CLOUDFUNCTIONS_NAME`            |                  | The name of the Cloud Function, if not empty, Google Cloud Functions is **enabled**                                                 |
| `gcp.cloudfunctions.minimumpriority` | `GCP_CLOUDFUNCTIONS_MINIMUMPRIORITY` | `""` (= `debug`) | Minimum priority of event for using this output, order is `emergency,alert,critical,error,warning,notice,informational,debug or ""` |

> [!NOTE]
The Env var values override the settings from yaml file.

## Example of config.yaml

```yaml
gcp:
  credentials: "" # The base64-encoded JSON key file for the GCP service account
  cloudfunctions:
    name: "" # The name of the Cloud Function, if not empty, GCP Cloud Functions is enabled
    # minimumpriority: "debug" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
```

## Additional info

## Screenshots
