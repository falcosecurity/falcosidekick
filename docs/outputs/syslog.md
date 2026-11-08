# Syslog

Sends each event as an RFC 5424 message over UDP or TCP; TCP uses octet-counting framing (RFC 6587), and `tls.enabled: true` runs it over TLS (RFC 5425, port 6514 by default). The severity follows the Falco priority. TCP keeps one connection and reconnects when the receiver closes it. Startup dials TCP receivers; an untrusted certificate stops startup. Syslog connects directly, without a proxy.

`format` is `json`, the event, or `cef`, ArcSight CEF:

- Device Vendor is `Falcosecurity` and Device Product `Falcosidekick`; Device Version is the Falcosidekick version; Device Event Class ID and Name are the rule; Severity follows the priority.
- `rt` is the event time in epoch milliseconds, `dvchost` the hostname, `msg` the output, cut at 1023 characters, `externalId` the event UUID and `cat` the Falco source.
- The first six output fields, in name order, go in `cs1` to `cs6` with the field name in `cs1Label` to `cs6Label`. The others, and the tags, go in keys starting with `FalcoFalcosidekick`, such as `FalcoFalcosidekickK8sNsName`: receivers keep them but may not index them.
- Values are escaped as the CEF specification asks: `\`, `=` and line breaks in the extension, `\` and `|` in the header.

## Example

<!-- example -->
```yaml
outputs:
  syslog:
    host: syslog.example.com
    tls:
      enabled: true
    format: cef
```

<!-- BEGIN GENERATED: settings -->
<!-- Generated from the output schema by `make docs`. Do not edit. -->

## Settings

Key in the output file: `syslog`. Category: Logs. UI event source: no. Batching: no.

| Setting | Type | Default | Description |
| --- | --- | --- | --- |
| `host` | string, **required** | - | Syslog receiver host name or IP address, without scheme, port or path. |
| `port` | integer | - | Receiver port. Empty or `0` uses `514`, or `6514` with `tls.enabled`. |
| `protocol` | one of `tcp`, `udp` | `tcp` | Transport for RFC 5424 messages. `tcp` keeps one connection with octet-counting framing, over TLS (RFC 5425) with `tls.enabled`; `udp` sends one datagram per message and cannot use TLS. |
| `format` | one of `json`, `cef` | `json` | Message body: the event JSON, or ArcSight CEF with the output fields in `cs1` to `cs6` and `FalcoFalcosidekick` keys. |
| `facility` | one of `auth`, `authpriv`, `cron`, `daemon`, `ftp`, `kern`, `local0`, `local1`, `local2`, `local3`, `local4`, `local5`, `local6`, `local7`, `lpr`, `mail`, `news`, `syslog`, `user`, `uucp` | `local0` | Syslog facility of every message; the severity follows the Falco priority. |
| `tls.enabled` | boolean | `false` | Connects over TLS. The other `tls` settings are refused unless this is set. |

Also takes the shared settings in [TLS](common.md#tls), [Delivery](common.md#delivery).

<!-- END GENERATED: settings -->
