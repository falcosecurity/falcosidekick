# OTLP (OpenTelemetry Protocol)

- **Category**: Traces, Logs, Metrics
- **Website**: <https://opentelemetry.io/>

## Table of content

- [OTLP (OpenTelemetry Protocol)](#otlp-opentelemetry-protocol)
  - [Table of content](#table-of-content)
  - [Overview](#overview)
  - [Signals](#signals)
    - [Traces](#traces)
    - [Logs](#logs)
    - [Metrics](#metrics)
  - [Additional info](#additional-info)

## Overview

Falcosidekick can export Falco events directly via [OpenTelemetry Protocol (OTLP)](https://opentelemetry.io/docs/specs/otel/protocol/), using the official OpenTelemetry Go SDK and exporters (`go.opentelemetry.io/otel`). This lets you forward Falco security events to any OTLP-compatible collector or backend (Grafana Tempo/Loki/Mimir, Prometheus, Jaeger, Datadog, and others) without an intermediate translation layer.

OTLP support is split into three independent signals, each configured and documented on its own page:

## Signals

### Traces

Forwards Falco events as OTLP traces (with an artificial span duration, since Falco events don't carry an end timestamp).

See [OTEL Traces](otlp_traces.md) for configuration, `config.yaml` example, and a full docker-compose stack (Falco + Falcosidekick + Grafana Tempo + Grafana).

### Logs

Forwards Falco events as OTLP log records.

See [OTEL Logs](otlp_logs.md) for configuration and setup details.

### Metrics

Exposes counters/metrics about Falco events via OTLP metrics, in addition to Falcosidekick's existing Prometheus/StatsD outputs.

See [OTEL Metrics](otlp_metrics.md) for configuration and a full docker-compose stack (Falco + Falcosidekick + OpenTelemetry Collector + Prometheus).

## Additional info

> [!NOTE]
Each signal (traces, logs, metrics) is enabled independently by setting its `endpoint` — you can enable one, two, or all three at once.

> [!WARNING]
Because of the way the OTEL SDK is structured, the OTLP outputs don't appear in Falcosidekick's own metrics (Prometheus, StatsD, ...) and error logs just specify `OTEL` as the output.
