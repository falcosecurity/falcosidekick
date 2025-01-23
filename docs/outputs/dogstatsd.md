# Dogstatsd

- **Category**: Metrics / Observability
- **Website**: https://docs.datadoghq.com/developers/dogstatsd/?tab=go

## Table of content

- [Dogstatsd](#dogstatsd)
  - [Table of content](#table-of-content)
  - [Configuration](#configuration)
  - [Example of config.yaml](#example-of-configyaml)
  - [Additional info](#additional-info)
  - [Screenshots](#screenshots)

## Configuration

| Setting               | Env var               | Default value    | Description                                                                                             |
| --------------------- | --------------------- | ---------------- | ------------------------------------------------------------------------------------------------------- |
| `dogstastd.forwarded` | `DOGSTASTD_FORWARDED` |                  | The address for the DogStatsD forwarder, in the form "host:port", if not empty DogStatsD is **enabled** |
| `dogstastd.namespace` | `DOGSTASTD_NAMESPACE` | `falcosidekick.` | A prefix for all metrics                                                                                |
| `dogstastd.tags`      | `DOGSTASTD_TAGS`      |                  | Comma separeted list of key:value to add as tags to the metrics                                         |

> [!NOTE]
The Env var values override the settings from yaml file.

## Example of config.yaml

```yaml
dogstatsd:
  forwarder: "" # The address for the DogStatsD forwarder, in the form "host:port", if not empty DogStatsD is enabled
  namespace: "falcosidekick." # A prefix for all metrics (default: "falcosidekick.")
  # tag : # Tags to add to the metrics
  #   key: "value"
```

## Additional info

## Screenshots
