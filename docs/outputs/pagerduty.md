# PagerDuty

Sends each event as an Events API v2 `trigger` event to `/v2/enqueue` on the `us` or `eu` host (`region`). The event UUID is the `dedup_key` and the severity follows the Falco priority. Not probed at startup: the Events API has no read route, so any request would open an alert.

## Example

<!-- example -->
```yaml
outputs:
  pagerduty:
    routing_key_file: /etc/falcosidekick/secrets/pagerduty/routing-key
    region: eu
```

<!-- BEGIN GENERATED: settings -->
<!-- Generated from the output schema by `make docs`. Do not edit. -->

## Settings

Key in the output file: `pagerduty`. Category: Alerting and on-call. UI event source: no. Batching: no.

| Setting | Type | Default | Description |
| --- | --- | --- | --- |
| `host` | string | - | Address of the destination as scheme, host and optional port. Empty uses the host of the selected region. |
| `base_path` | string | - | Path prefix of every request, such as `/proxy/v2` when the destination sits behind a reverse proxy. |
| `routing_key` | string, secret, **required** | - | Integration key of an Events API v2 integration on the service or ruleset, sent as `routing_key` in every event. Also accepted as `routing_key_file`, the path of a file holding the value. |
| `region` | one of `us`, `eu` | `us` | Region of the service account. It sets the host when the host is empty. |

Also takes the shared settings in [Query parameters](common.md#query-parameters), [HTTP authentication and headers](common.md#http-authentication-and-headers), [TLS](common.md#tls), [Delivery](common.md#delivery).

<!-- END GENERATED: settings -->
