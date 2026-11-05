# Outputs

Fields, defaults and comments for every output are in [`config_example_outputs.yaml`](../config_example_outputs.yaml). This page covers behavior and the server versions the beta was tested against.

## Tested versions

Each version below runs in CI ([`e2e.yml`](../.github/workflows/e2e.yml)): an event goes into the binary and the test reads it back from the destination's own API.

| Output | Versions | Covered |
| --- | --- | --- |
| Webhook | strict local fake | delivery, headers, failures |
| Slack | strict local fake | payload, failures |
| Loki | 3.7.9, 2.9.17 | push, labels, tenants with `auth_enabled`, wrong path |
| Alertmanager | v0.34.2, v0.33.1 | labels, annotations, expiry, fan-out to several hosts |
| Kafka | 4.4.0, 3.9.2 | sync and async, acks, compression, SASL PLAIN and SCRAM, TLS |
| Elasticsearch | 7.17.28, 8.19.23, 9.5.5 | single and bulk, index template, basic auth, API key, TLS |
| OpenSearch | 2.19.7, 3.9.0 | single and bulk, basic auth, TLS, client certificate |

Older servers may work but are not tested.

## HTTP outputs

Webhook, Slack, Loki, Elasticsearch and Alertmanager share the target fields: `host` (scheme, host and port only), `base_path`, `endpoint` or `secret_endpoint`, `query_params`, headers, TLS and `_file` secrets. Values marked secret are never returned by the API. Only a 2xx answer counts as delivered; redirects to another origin are refused.

## Webhook

Posts the event as JSON. `method: PUT` is accepted.

## Slack

Posts to an incoming webhook; `host` defaults to `https://hooks.slack.com` and the path goes in `secret_endpoint`.

## Loki

Pushes to `/loki/api/v1/push` under `base_path`; `tenant` sets `X-Scope-OrgID`. The health probe is `GET /ready`.

## Elasticsearch and OpenSearch

- Each event is indexed with its UUID as document id (`create`). A retried batch does not duplicate documents; an item already indexed counts as delivered.
- In a bulk request, one item rejected for good marks the whole batch as failed.
- `create_index_template: true` installs a template once, if none with that name exists. `number_of_shards` and `number_of_replicas` default to 3.
- Authentication: basic auth, `api_key` or a client certificate; combining `api_key` with basic auth, `bearer_token` or an `Authorization` header is rejected.

## Alertmanager

- Posts to every host in `hosts`. The event counts as sent when at least one host accepts it; a failing host sets the output `degraded` with `last_warning` until a delivery reaches every host.
- Label values (`alertname`, `rule`, `extra_labels`) are sent as they are; label names are sanitized.
- The health probe is `GET /-/healthy` on each host.

## Kafka

- Sync (default) waits for the broker acknowledgement. `producer.delivery_timeout` (default 10s, minimum 1s) bounds each record and the flush on shutdown.
- `producer.async: true` does not wait: an event counts as sent once buffered, and a later broker failure is counted as failed. Choose sync for exact counters.
- Idempotent writes are on only with sync and `required_acks: all`.
- Client warnings and errors (connection, TLS, SASL) go to the Falcosidekick log.
