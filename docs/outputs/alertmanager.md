# Alertmanager

Sends each event as an alert to one or more Prometheus Alertmanager instances.

- Posts to every host in `hosts`. The event counts as sent when at least one host accepts it; a failing host sets the output `degraded` with `last_warning` until a delivery reaches every host.
- Label values (`alertname`, `rule`, `extra_labels`) are sent as they are; label names are sanitized.
- The health probe is `GET /-/healthy` on each host.
- `expires_after` sets `endsAt` that many seconds after the event. With `0` the alert has no `endsAt`, and Alertmanager resolves it after its `resolve_timeout` (5m by default) unless it is sent again.

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
| `expires_after` | integer | `0` | Seconds after the event time at which the alert ends, sent as `endsAt`. `0` sends no end time, so Alertmanager resolves the alert after its `resolve_timeout`. |
| `extra_labels` | map by name | - | Labels added to every alert, by label name; they replace built-in labels of the same name. Characters other than letters, digits and `_` in names become `_`. |
| `extra_annotations` | map by name | - | Annotations added to every alert, by name; they replace the built-in `info`, `description` and `summary` of the same name. |
| `custom_severity_map` | map by name | - | Value of the `severity` label by lowercase Falco priority, such as `critical: P1`. Priorities not listed get `critical`, `warning` or `information`. |

Also takes the shared settings in [Query parameters](common.md#query-parameters), [HTTP authentication and headers](common.md#http-authentication-and-headers), [TLS](common.md#tls), [Delivery](common.md#delivery).

<!-- END GENERATED: settings -->
