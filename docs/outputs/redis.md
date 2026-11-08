# Redis

Stores the event JSON under `key` with `storage_type` `stream` (`XADD`, the default), `list` (`RPUSH`) or `hash` (`HSET`, field = event UUID). A batch goes out in one pipeline.

- `key` has no default: pick one per Falcosidekick, such as `falco`, so two instances do not share it by accident.
- The stream keeps about `max_len` entries, 100000 unless set, with `XADD MAXLEN ~`: Redis trims whole nodes, so the length can briefly exceed it. `max_len: 0` keeps every entry. Lists and hashes are not trimmed.

- Startup sends `PING`: rejected credentials, a missing ACL permission or an unknown database stop startup.
- A `WRONGTYPE`, `WRONGPASS`, `NOAUTH` or `NOPERM` reply fails the event for good; every other reply, such as `BUSY`, `LOADING` or `OOM`, is retried.
- A retry sends the whole batch again, so with `stream` and `list` an event whose command went through is written twice; `hash` overwrites the same field.
- `tls.enabled: true` connects over TLS; the other `tls` settings without it are refused at startup.
- Redis connects directly, without a proxy.

Tested with Redis 7.4 and 8.

## Example

<!-- example -->
```yaml
outputs:
  redis:
    address: redis:6379
    password_file: /etc/falcosidekick/secrets/redis/password
    key: falco
```

<!-- BEGIN GENERATED: settings -->
<!-- Generated from the output schema by `make docs`. Do not edit. -->

## Settings

Key in the output file: `redis`. Category: Storage. UI event source: no. Batching: yes.

| Setting | Type | Default | Description |
| --- | --- | --- | --- |
| `address` | string, **required** | - | Redis server as `host:port`, without scheme or credentials. |
| `username` | string | - | ACL user; requires a password. Empty authenticates as the default user when a password is set. |
| `password` | string, secret | - | Password sent with `AUTH`, for the ACL user or the default user. Empty sends no `AUTH`. Also accepted as `password_file`, the path of a file holding the value. |
| `database` | integer | `0` | Database number selected on each connection, `0` or greater. |
| `storage_type` | one of `stream`, `list`, `hash` | `stream` | How the event JSON is stored under `key`: `stream` adds an entry with field `event` with `XADD`, `list` appends with `RPUSH`, `hash` sets the event UUID field with `HSET`. |
| `key` | string, **required** | - | Name of the stream, list or hash that receives the events. Suggested: `falco`. |
| `max_len` | integer | `100000` | Approximate stream length kept by `XADD MAXLEN ~`, trimming the oldest entries; `0` keeps every entry. Only with `storage_type` `stream`. |
| `tls.enabled` | boolean | `false` | Connects over TLS. The other `tls` settings are refused unless this is set. |

Also takes the shared settings in [TLS](common.md#tls), [Delivery](common.md#delivery), [Batching](common.md#batching).

<!-- END GENERATED: settings -->
