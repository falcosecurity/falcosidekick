# Datadog

Sends each event to Datadog as an event.

- Without `app_key`: Events API v1 (`/api/v1/events`), which Datadog marks deprecated and keeps for organizations that already used it.
- With `app_key`: Events API v2 on the event intake host, with `category: alert` and the event UUID as `aggregation_key`.
- `site` selects the hosts; `host` overrides both.
- Startup validates the API key (`/api/v1/validate`) and, with `app_key`, both keys (`/api/v2/validate_keys`).

## Example

<!-- example -->
```yaml
outputs:
  datadog:
    site: datadoghq.eu
    api_key_file: /etc/falcosidekick/secrets/datadog/api-key
    app_key_file: /etc/falcosidekick/secrets/datadog/app-key
```

<!-- BEGIN GENERATED: settings -->
<!-- Generated from the output schema by `make docs`. Do not edit. -->

## Settings

Key in the output file: `datadog`. Category: Alerting and on-call. UI event source: no. Batching: no.

| Setting | Type | Default | Description |
| --- | --- | --- | --- |
| `host` | string | - | Address that replaces every Datadog host, as scheme, host and optional port, such as a proxy. Empty uses the hosts of the site. |
| `base_path` | string | - | Path prefix of every request, such as `/proxy/v2` when the destination sits behind a reverse proxy. |
| `api_key` | string, secret, **required** | - | Datadog API key, sent in the `DD-API-KEY` header. Also accepted as `api_key_file`, the path of a file holding the value. |
| `app_key` | string, secret | - | Datadog application key, sent in the `DD-APPLICATION-KEY` header. When set, events go to Events API v2 on `event-management-intake.<site>`; empty uses v1 on `api.<site>`. Also accepted as `app_key_file`, the path of a file holding the value. |
| `site` | one of `datadoghq.com`, `us3.datadoghq.com`, `us5.datadoghq.com`, `datadoghq.eu`, `ap1.datadoghq.com`, `ap2.datadoghq.com`, `uk1.datadoghq.com`, `ddog-gov.com`, `us2.ddog-gov.com` | `datadoghq.com` | Datadog site of the organization, which selects the API hosts. |

Also takes the shared settings in [Query parameters](common.md#query-parameters), [HTTP authentication and headers](common.md#http-authentication-and-headers), [TLS](common.md#tls), [Delivery](common.md#delivery).

<!-- END GENERATED: settings -->
