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

This output has no specific configuration settings.

> [!NOTE]
The Env var values override the settings from yaml file.

## Example of config.yaml

```yaml
prometheus:
```

## Additional info

> [!NOTE]
This output is used to collect metrics about Falco events and Falcosidekick outputs in prometheus format, scrape the endpoint `/metrics` to collect them.

## Screenshots
