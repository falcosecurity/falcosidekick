# Elasticsearch

Indexes each event in Elasticsearch or OpenSearch.

- Each event is indexed with its UUID as document id (`create`). A retried batch does not duplicate documents; an item already indexed counts as delivered.
- In a bulk request, one item rejected for good marks the whole batch as failed.
- `create_index_template: true` installs a template once, if none with that name exists.
- Authentication: basic auth, `api_key` or a client certificate; combining `api_key` with basic auth, `bearer_token` or an `Authorization` header is rejected.

Tested with Elasticsearch 7.17.28, 8.19.23 and 9.5.5, and OpenSearch 2.19.7 and 3.9.0.

## Example

<!-- example -->
```yaml
outputs:
  elasticsearch:
    host: https://elasticsearch:9200
    index: falco
    index_suffix: daily
    username: falcosidekick
    password_file: /etc/falcosidekick/secrets/elasticsearch/password
    runtime:
      batching:
        enabled: true
```

<!-- BEGIN GENERATED: settings -->
<!-- Generated from the output schema by `make docs`. Do not edit. -->

## Settings

Key in the output file: `elasticsearch`. Category: Logs. UI event source: no. Batching: yes.

| Setting | Type | Default | Description |
| --- | --- | --- | --- |
| `host` | string, **required** | - | Address of the destination as scheme, host and optional port, such as `https://example.com:8443`; the path goes in the base path and endpoint. |
| `base_path` | string | - | Path prefix of every request, such as `/proxy/v2` when the destination sits behind a reverse proxy. |
| `index` | string | `falco` | Index the events are written to, before the date suffix: lowercase letters, digits, `.`, `-` and `_`, starting with a letter or digit. |
| `index_suffix` | one of `daily`, `monthly`, `annually`, `none` | `daily` | Date added to the index at delivery time, in UTC: `-YYYY.MM.DD`, `-YYYY.MM` or `-YYYY`. `none` writes to the index itself. |
| `pipeline` | string | - | Ingest pipeline every document goes through, sent as the `pipeline` query parameter. Empty uses the index default. |
| `api_key` | string, secret | - | Elasticsearch API key in its encoded form, sent as `Authorization: ApiKey <key>`. Also accepted as `api_key_file`, the path of a file holding the value. |
| `flatten_fields` | boolean | `false` | Replaces `.` with `_` in output field names, such as `proc_name`, so they are stored as flat fields instead of nested objects. |
| `create_index_template` | boolean | `false` | Creates an index template named after the index, with the shard and replica counts and the event mappings, before the first delivery. An existing template is left unchanged. |
| `number_of_shards` | integer | `3` | Primary shards of each new index, set in the created template; must be greater than `0`. Used only when the template is created. |
| `number_of_replicas` | integer | `3` | Replicas of each primary shard, set in the created template; `0` keeps no replica. Used only when the template is created. |

Also takes the shared settings in [Query parameters](common.md#query-parameters), [HTTP authentication and headers](common.md#http-authentication-and-headers), [TLS](common.md#tls), [Delivery](common.md#delivery), [Batching](common.md#batching).

<!-- END GENERATED: settings -->
