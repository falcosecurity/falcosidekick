# In-memory store

Keeps the latest events in a ring buffer in memory, where the UI and the events API read them: it is the output to name in `ui.event_source`. Events are lost on restart and each replica keeps its own. Once the buffer is full, each new event replaces the oldest; with `ttl` set, older events are also removed in the background.

## Example

<!-- example -->
```yaml
outputs:
  inmemory:
    capacity: 10000
    ttl: 24h
```

<!-- BEGIN GENERATED: settings -->
<!-- Generated from the output schema by `make docs`. Do not edit. -->

## Settings

Key in the output file: `inmemory`. Category: Storage. UI event source: yes. Batching: no.

| Setting | Type | Default | Description |
| --- | --- | --- | --- |
| `capacity` | integer, **required** | `10000` | Number of events kept in memory; once full, each new event replaces the oldest. `0` uses the default. |
| `ttl` | string | `0` | Go duration, such as `24h`, after which an event is removed, measured from the event time. `0` keeps events until replaced. |
| `gc_interval` | string | `10s` | Go duration, such as `10s`, between removals of expired events; refused without `ttl`. `0` uses the default. |

Also takes the shared settings in [Delivery](common.md#delivery).

<!-- END GENERATED: settings -->
