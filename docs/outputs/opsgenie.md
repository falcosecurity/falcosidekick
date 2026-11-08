# Opsgenie

Creates an alert per event with `/v2/alerts` on the `us` or `eu` host. Atlassian ends Opsgenie on 2027-04-05 (sales stopped on 2025-06-04).

- The event UUID is the `alias`, so a retried event updates the same alert.
- Startup calls `GET /v2/heartbeats`: 401 or 404 stops startup; 403, the answer for an alert-only key, is accepted.

## Example

<!-- example -->
```yaml
outputs:
  opsgenie:
    api_key_file: /etc/falcosidekick/secrets/opsgenie/api-key
    region: eu
```

<!-- BEGIN GENERATED: settings -->
<!-- Generated from the output schema by `make docs`. Do not edit. -->

## Settings

Key in the output file: `opsgenie`. Category: Alerting and on-call. UI event source: no. Batching: no.

| Setting | Type | Default | Description |
| --- | --- | --- | --- |
| `host` | string | - | Address of the destination as scheme, host and optional port. Empty uses the host of the selected region. |
| `base_path` | string | - | Path prefix of every request, such as `/proxy/v2` when the destination sits behind a reverse proxy. |
| `api_key` | string, secret, **required** | - | Key of an Opsgenie API integration, sent as `Authorization: GenieKey <key>`. Also accepted as `api_key_file`, the path of a file holding the value. |
| `region` | one of `us`, `eu` | `us` | Region of the service account. It sets the host when the host is empty. |

Also takes the shared settings in [Query parameters](common.md#query-parameters), [HTTP authentication and headers](common.md#http-authentication-and-headers), [TLS](common.md#tls), [Delivery](common.md#delivery).

<!-- END GENERATED: settings -->
