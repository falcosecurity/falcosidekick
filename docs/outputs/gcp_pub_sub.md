# GCP PubSub

- **Category**: Message queue / Streaming
- **Website**: https://cloud.google.com/pubsub

## Table of content

- [GCP PubSub](#gcp-pubsub)
  - [Table of content](#table-of-content)
  - [Configuration](#configuration)
  - [Example of config.yaml](#example-of-configyaml)
  - [Additional info](#additional-info)
  - [Screenshots](#screenshots)

## Configuration

| Setting                       | Env var                       | Default value    | Description                                                                                                                         |
| ----------------------------- | ----------------------------- | ---------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `gcp.credentials`             | `GCP_CREDENTIALS`             |                  | The base64-encoded JSON key file for the GCP service account                                                                        |
| `gcp.pubsub.projectid`        | `GCP_PUBSUB_PROJECTID`        |                  | The GCP Project ID containing the Pub/Sub Topic, if not empty, GCP PubSub is **enabled**                                            |
| `gcp.pubsub.topic`            | `GCP_PUBSUB_TOPIC`            |                  | The name of the Pub/Sub topic                                                                                                       |
| `gcp.pubsub.customattributes` | `GCP_PUBSUB_CUSTOMATTRIBUTES` |                  | Custom attributes to add to the Pub/Sub messages                                                                                    |
| `gcp.pubsub.minimumpriority`  | `GCP_PUBSUB_MINIMUMPRIORITY`  | `""` (= `debug`) | Minimum priority of event for using this output, order is `emergency,alert,critical,error,warning,notice,informational,debug or ""` |

> [!NOTE]
The Env var values override the settings from yaml file.

## Example of config.yaml

```yaml
gcp:
  credentials: "" # The base64-encoded JSON key file for the GCP service account
  pubsub:
    projectid: "" # The GCP Project ID containing the Pub/Sub Topic, if not empty, GCP PubSub is enabled
    topic: "" # The name of the Pub/Sub topic
    # customattributes: # Custom attributes to add to the Pub/Sub messages
    #   key: value
    # minimumpriority: "debug" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
```

## Additional info

## Screenshots
