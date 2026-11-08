# Datadog

Sends each event to Datadog Events API v2 (`POST /api/v2/events` on `event-management-intake.<site>`) as an alert event. Events API v2 needs both `api_key` and `app_key`; the deprecated v1 API is not used.

- `title` is the rule (500 characters at most), `message` the output (4000), `timestamp` the event time, `host` the hostname and `aggregation_key` the event UUID (100), so a retried event is deduplicated.
- `status` is `error` (Emergency to Error), `warn` (Warning) or `ok` (Notice and below); `priority` runs from `1` (Emergency, Alert) to `5` (Notice and below).
- Tags are `falco_source:<source>` (Datadog reserves `source`) and the rule tags, at most 100 tags of at most 200 characters. Output fields go in `attributes.custom.output_fields`, not in tags.
- Datadog refuses events with a `timestamp` older than 18 hours.
- `site` selects the hosts; `host` overrides both.
- Startup validates both keys with `GET /api/v2/validate_keys` on `api.<site>`.

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
| `app_key` | string, secret, **required** | - | Datadog application key, sent in the `DD-APPLICATION-KEY` header; Events API v2 requires it with the API key. Also accepted as `app_key_file`, the path of a file holding the value. |
| `site` | one of `datadoghq.com`, `us3.datadoghq.com`, `us5.datadoghq.com`, `datadoghq.eu`, `ap1.datadoghq.com`, `ap2.datadoghq.com`, `uk1.datadoghq.com`, `ddog-gov.com`, `us2.ddog-gov.com` | `datadoghq.com` | Datadog site of the organization, which selects the API hosts. |

Also takes the shared settings in [Query parameters](common.md#query-parameters), [HTTP authentication and headers](common.md#http-authentication-and-headers), [TLS](common.md#tls), [Delivery](common.md#delivery).

<!-- END GENERATED: settings -->
