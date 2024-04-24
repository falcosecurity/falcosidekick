# Prometheus

- **Category**: Metrics / Observability
- **Website**: https://prometheus.io/

## Table of content

- [Prometheus](#prometheus)
  - [Table of content](#table-of-content)
  - [Configuration](#configuration)
  - [Example of config.yaml](#example-of-configyaml)
  - [Additional info](#additional-info)
  - [Screenshots](#screenshots)

## Configuration

| Setting                  | Env var                  | Default value | Description                                                                                                    |
| ------------------------ | ------------------------ | ------------- | -------------------------------------------------------------------------------------------------------------- |
| `prometheus.extralabels` | `PROMETHEUS_EXTRALABELS` |               | Comma separated list of fields to use as labels additionally to rule, source, priority, tags and custom_fields |

> [!NOTE]
The Env var values override the settings from yaml file.

## Example of config.yaml

```yaml
prometheus:
  # extralabels: "" # comma separated list of fields to use as labels additionally to rule, source, priority, tags and custom_fields
```

## Additional info

> [!NOTE]
This output is used to collect metrics about Falco events and Falcosidekick outputs in prometheus format, scrape the endpoint `/metrics` to collect them.

## Screenshots
