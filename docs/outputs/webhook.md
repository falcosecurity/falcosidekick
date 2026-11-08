# Webhook

Sends each event as JSON to an HTTP endpoint, with `POST` or, if set, `PUT`. Only a 2xx answer counts as delivered.

## Example

<!-- example -->
```yaml
outputs:
  webhook:
    host: https://events.example.com
    endpoint: /falco
    headers:
      Authorization:
        files:
          - /etc/falcosidekick/secrets/webhook/authorization
```

<!-- BEGIN GENERATED: settings -->
<!-- Generated from the output schema by `make docs`. Do not edit. -->

## Settings

Key in the output file: `webhook`. Category: Webhooks. UI event source: no. Batching: no.

| Setting | Type | Default | Description |
| --- | --- | --- | --- |
| `host` | string, **required** | - | Address of the destination as scheme, host and optional port, such as `https://example.com:8443`; the path goes in the base path and endpoint. |
| `base_path` | string | - | Path prefix of every request, such as `/proxy/v2` when the destination sits behind a reverse proxy. |
| `endpoint` | string | `/` | Path the events are sent to, after the base path. |
| `secret_endpoint` | string, secret | - | Path the events are sent to, used instead of the endpoint when the path itself is a credential, as in a webhook URL; the API never returns it. Also accepted as `secret_endpoint_file`, the path of a file holding the value. |
| `method` | one of `POST`, `PUT` | `POST` | HTTP method of the request that carries each event as a JSON body, in uppercase. |

Also takes the shared settings in [Query parameters](common.md#query-parameters), [HTTP authentication and headers](common.md#http-authentication-and-headers), [TLS](common.md#tls), [Delivery](common.md#delivery).

<!-- END GENERATED: settings -->
