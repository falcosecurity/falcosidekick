# Email (SMTP)

Sends one email per event, HTML or text. The subject is `[Priority] rule on hostname`, without `on hostname` when the event has none.

- `tls_mode` is `starttls` (required), `implicit`, `opportunistic` or `none`. Credentials are sent only over TLS or to localhost.
- Startup connects, negotiates TLS and authenticates without sending mail: rejected credentials, a missing STARTTLS or an untrusted certificate stop startup.
- A 5yz reply fails the event for good, a 4yz reply is retried. With several recipients a refused recipient is retried: the client library reports only the last recipient's reply.
- SMTP connects directly, without a proxy.

Tested with Mailpit v1.33.0.

## Example

<!-- example -->
```yaml
outputs:
  smtp:
    host: smtp.example.com
    username: falcosidekick@example.com
    password_file: /etc/falcosidekick/secrets/smtp/password
    from: Falco <falcosidekick@example.com>
    to:
      - security@example.com
```

<!-- BEGIN GENERATED: settings -->
<!-- Generated from the output schema by `make docs`. Do not edit. -->

## Settings

Key in the output file: `smtp`. Category: Email. UI event source: no. Batching: no.

| Setting | Type | Default | Description |
| --- | --- | --- | --- |
| `host` | string, **required** | - | SMTP server host name or IP address, without scheme or port. Also the name verified in the server certificate. |
| `port` | integer | - | SMTP server port. Empty or `0` uses `587` with `starttls` and `opportunistic`, `465` with `implicit`, `25` with `none`. |
| `tls_mode` | one of `starttls`, `implicit`, `opportunistic`, `none` | `starttls` | `starttls` requires STARTTLS, `implicit` connects over TLS, `opportunistic` uses STARTTLS when offered, `none` sends in clear and refuses `tls` settings. |
| `auth_mechanism` | one of `plain`, `xoauth2`, `none` | `plain` | `plain` needs username and password, `xoauth2` needs username and token with `starttls` or `implicit`, `none` sends no credentials. Credentials go only over TLS, except to localhost. |
| `username` | string | - | Account name for `plain` or `xoauth2` authentication. |
| `password` | string, secret | - | Password for `plain` authentication. Also accepted as `password_file`, the path of a file holding the value. |
| `token` | string, secret | - | OAuth 2.0 access token for `xoauth2` authentication. Also accepted as `token_file`, the path of a file holding the value. |
| `from` | string, **required** | - | One RFC 5322 address for the `From` header and envelope sender, such as `Falco <falco@example.com>`. |
| `to` | list of strings, **required** | - | Recipients, one RFC 5322 address per entry. All receive the same message. |
| `output_format` | one of `html`, `text` | `html` | `html` sends a multipart message with text and HTML parts; `text` sends plain text only. |

Also takes the shared settings in [TLS](common.md#tls), [Delivery](common.md#delivery).

<!-- END GENERATED: settings -->
