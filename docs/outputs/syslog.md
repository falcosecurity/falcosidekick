# Syslog

Sends each event as an RFC 5424 message over UDP, TCP or TLS; TCP and TLS use octet-counting framing (RFC 6587). `format` is `json` (the event) or `cef`. The severity follows the Falco priority. TCP and TLS keep one connection and reconnect when the receiver closes it. Startup dials TCP and TLS receivers; an untrusted certificate stops startup. Syslog connects directly, without a proxy.

## Example

<!-- example -->
```yaml
outputs:
  syslog:
    host: syslog.example.com
    protocol: tls
    format: cef
```

<!-- BEGIN GENERATED: settings -->
<!-- Generated from the output schema by `make docs`. Do not edit. -->

## Settings

Key in the output file: `syslog`. Category: Logs. UI event source: no. Batching: no.

| Setting | Type | Default | Description |
| --- | --- | --- | --- |
| `host` | string, **required** | - | Syslog receiver host name or IP address, without scheme, port or path. |
| `port` | integer | - | Receiver port. Empty or `0` uses `514`, or `6514` with protocol `tls`. |
| `protocol` | one of `tcp`, `udp`, `tls` | `tcp` | Transport for RFC 5424 messages. `tcp` and `tls` keep one connection with octet-counting framing; `tls` is required for `tls` settings. |
| `format` | one of `json`, `cef` | `json` | Message body: the event JSON, or ArcSight CEF. |
| `facility` | one of `auth`, `authpriv`, `cron`, `daemon`, `ftp`, `kern`, `local0`, `local1`, `local2`, `local3`, `local4`, `local5`, `local6`, `local7`, `lpr`, `mail`, `news`, `syslog`, `user`, `uucp` | `local0` | Syslog facility of every message; the severity follows the Falco priority. |

Also takes the shared settings in [TLS](common.md#tls), [Delivery](common.md#delivery).

<!-- END GENERATED: settings -->
