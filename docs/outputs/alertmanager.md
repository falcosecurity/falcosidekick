# Alertmanager

Sends each event as an alert to one or more Prometheus Alertmanager instances.

- Posts to every host in `hosts`. The event counts as sent when at least one host accepts it; a failing host sets the output `degraded` with `last_warning` until a delivery reaches every host.
- Labels: `alertname` (the rule), `source`, `priority` (as Falco writes it, such as `Warning`), `severity`, `hostname` and `tags`. Annotations: `summary` (the rule) and `description` (the output).
- `severity` is `critical` (Emergency, Alert, Critical), `warning` (Error, Warning) or `info` (Notice and below), the values of the monitoring mixins; `custom_severity_map` overrides it. Its keys are Falco priorities in any case, `info` included; a key that names no priority, or a priority twice, is refused at startup.
- Label values are sent as they are. Names in `extra_labels` must match `[a-zA-Z_][a-zA-Z0-9_]*`; any other name fails the configuration.
- The health probe is `GET /-/healthy` on each host.
- `expires_after` is a Go duration, such as `30m`, that sets `endsAt` after the event time. With `0` the alert has no `endsAt`, and Alertmanager resolves it after its `resolve_timeout` (5m by default) unless it is sent again.

Tested with Alertmanager v0.34.2 and v0.33.1.

## Example

<!-- example -->
```yaml
outputs:
  alertmanager:
    hosts:
      - http://alertmanager:9093
    extra_labels:
      team: security
```

<!-- BEGIN GENERATED: settings -->
<!-- Generated from the output schema by `make docs`. Do not edit. -->

## Settings

Key in the output file: `alertmanager`. Category: Alerting and on-call. UI event source: no. Batching: no.

| Setting | Type | Default | Description |
| --- | --- | --- | --- |
| `base_path` | string | - | Path prefix of every request, such as `/proxy/v2` when the destination sits behind a reverse proxy. |
| `endpoint` | string | `/api/v2/alerts` | Path the events are sent to, after the base path. |
| `secret_endpoint` | string, secret | - | Path the events are sent to, used instead of the endpoint when the path itself is a credential, as in a webhook URL; the API never returns it. Also accepted as `secret_endpoint_file`, the path of a file holding the value. |
| `hosts` | list of strings, **required** | - | Alertmanager instances, each as scheme, host and optional port such as `http://alertmanager:9093`. Every alert goes to all of them and counts as delivered when at least one accepts it. |
| `generator_url` | string | - | Link sent as the `generatorURL` of every alert; Alertmanager shows it as the alert source. |
| `expires_after` | string | `0` | Go duration, such as `30m`, after the event time at which the alert ends, sent as `endsAt`. `0` sends no end time, so Alertmanager resolves the alert after its `resolve_timeout`. |
| `extra_labels` | map by name | - | Labels added to every alert, by label name; they replace built-in labels of the same name. Names must match `[a-zA-Z_][a-zA-Z0-9_]*`. |
| `extra_annotations` | map by name | - | Annotations added to every alert, by name; they replace the built-in `summary` and `description` of the same name. |
| `custom_severity_map` | map by name | - | Value of the `severity` label by Falco priority, in any case, such as `critical: P1`; other keys are refused. Priorities not listed get `critical`, `warning` or `info`. |

Also takes the shared settings in [Query parameters](common.md#query-parameters), [HTTP authentication and headers](common.md#http-authentication-and-headers), [TLS](common.md#tls), [Delivery](common.md#delivery).

<!-- END GENERATED: settings -->
