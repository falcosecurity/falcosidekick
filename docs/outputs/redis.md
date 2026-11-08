# Redis

Stores the event JSON with `storage_type` `list` (`RPUSH`), `hashmap` (`HSET`, field = event UUID) or `stream` (`XADD`, optional `max_len`). A batch goes out in one pipeline.

- Startup sends `PING`: rejected credentials, a missing ACL permission or an unknown database stop startup.
- A `WRONGTYPE`, `WRONGPASS`, `NOAUTH` or `NOPERM` reply fails the event for good; every other reply, such as `BUSY`, `LOADING` or `OOM`, is retried.
- A retry sends the whole batch again, so with `list` and `stream` an event whose command went through is written twice; `hashmap` overwrites the same field.
- `tls` settings need `tls_enabled: true`.
- Redis connects directly, without a proxy.

Tested with Redis 7.4 and 8.

## Example

<!-- example -->
```yaml
outputs:
  redis:
    address: redis:6379
    password_file: /etc/falcosidekick/secrets/redis/password
    storage_type: stream
    max_len: 100000
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
| `storage_type` | one of `list`, `hashmap`, `stream` | `list` | How the event JSON is stored under `key`: `list` appends with `RPUSH`, `hashmap` sets the event UUID field with `HSET`, `stream` adds an entry with field `event` with `XADD`. |
| `key` | string | `falco` | Name of the list, hash or stream that receives the events. |
| `max_len` | integer | `0` | Approximate stream length kept by `XADD MAXLEN ~`, trimming the oldest entries. Only with `storage_type` `stream`. |
| `tls_enabled` | boolean | `false` | Connects to Redis over TLS. `tls` settings are refused unless this is set. |

Also takes the shared settings in [TLS](common.md#tls), [Delivery](common.md#delivery), [Batching](common.md#batching).

<!-- END GENERATED: settings -->
