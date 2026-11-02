# Falcosidekick

[![Falco Ecosystem Repository](https://github.com/falcosecurity/evolution/blob/main/repos/badges/falco-ecosystem-blue.svg)](https://github.com/falcosecurity/evolution/blob/main/REPOSITORIES.md#ecosystem-scope)

![falcosidekick](imgs/falcosidekick_color.png)

Falcosidekick connects [Falco](https://github.com/falcosecurity/falco) to your ecosystem. It receives Falco events over HTTP and forwards them to the outputs you configure.

This branch holds Falcosidekick v3, currently in beta. The v3 image includes a built-in web UI.

## Versions

| Version | Branch | Status | Image tags |
| --- | --- | --- | --- |
| v3 | `master` | Beta | `v3-*` |
| v2 | [`2.x`](https://github.com/falcosecurity/falcosidekick/tree/2.x) | Maintenance, security and critical fixes only | `latest`, `2.*` |

v2 configuration is not compatible with v3.

## Outputs

Webhook, Slack, Loki, Elasticsearch, Alertmanager and Kafka.

## Build

Requires Go and [Bun](https://bun.sh).

```sh
make falcosidekick-v3       # binary with the web UI
make falcosidekick-v3-slim  # binary without the web UI
```

## Configuration

See [`config_example_sidekick.yaml`](config_example_sidekick.yaml) for the service and [`config_example_outputs.yaml`](config_example_outputs.yaml) for outputs.

## Development

```sh
make v3-verify-full
```

## License

[Apache License 2.0](LICENSE)
