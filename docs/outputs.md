# Outputs

Fields, defaults and comments for every output are in [`config_example_outputs.yaml`](../config_example_outputs.yaml). This page covers behavior and the tested server versions.

## Tested server versions

| Output | Versions |
| --- | --- |
| Loki | 3.7.9, 2.9.17 |
| Alertmanager | v0.34.2, v0.33.1 |
| Kafka | 4.4.0, 3.9.2 |
| Elasticsearch | 7.17.28, 8.19.23, 9.5.5 |
| OpenSearch | 2.19.7, 3.9.0 |

Older servers may work but are not tested.

## HTTP outputs

All HTTP outputs share the target fields: `host` (scheme, host and port only), `base_path`, `endpoint` or `secret_endpoint`, `query_params`, headers, TLS and `_file` secrets. Values marked secret are never returned by the API. Only a 2xx answer counts as delivered; redirects to another origin are refused.

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

## Microsoft Teams

Posts an Adaptive Card to a Teams Workflows (Power Automate) webhook; the retired Office 365 connector `MessageCard` is not supported. `host` is required (it varies per tenant), the workflow path goes in `secret_endpoint` and the `sig` query parameter must be a secret or a file. Workflows answers 202 once the flow run is queued: a run that fails later is visible only in the flow history. Messages are capped below the 28 KB Teams limit, dropping output fields first. Not probed at startup.

## Discord

Posts embeds to a webhook; `host` defaults to `https://discord.com`, the path with the token goes in `secret_endpoint`. Startup reads the webhook with `GET`, which posts nothing: a wrong token or a deleted webhook stops startup. Embeds stay within the documented limits.

## Grafana OnCall

Posts to the formatted webhook integration (Grafana OnCall OSS, archived on 2026-03-24, and Grafana Cloud IRM use the same format). The token path goes in `secret_endpoint`; `bearer_token` sends a service account token when the integration requires one. Not probed at startup.

## PagerDuty

Sends Events API v2 `trigger` events to `/v2/enqueue` on the `us` or `eu` host (`region`). `routing_key` is a secret. The event UUID is the `dedup_key` and severity follows the Falco priority. Not probed at startup: the Events API has no read route, so any request would open an alert.

## Opsgenie

Atlassian ends Opsgenie on 2027-04-05 (sales stopped on 2025-06-04). Creates alerts with `/v2/alerts` on the `us` or `eu` host, `api_key` sent as `GenieKey`. The event UUID is the `alias`, so a retried event updates the same alert. Startup calls `GET /v2/heartbeats`: 401 or 404 stops startup; 403, the answer for an alert-only key, is accepted.

## Datadog

- Without `app_key`: Events API v1 (`/api/v1/events`), which Datadog marks deprecated and keeps for organizations that already used it.
- With `app_key`: Events API v2 on the event intake host, with `category: alert` and the event UUID as `aggregation_key`.
- `site` selects the hosts; `host` overrides both. Startup validates the API key (`/api/v1/validate`) and, with `app_key`, both keys (`/api/v2/validate_keys`).

## Falco Talon

Posts the Falco event as Falco sends it to `/` (configurable). Startup calls `GET /healthz`.

## CloudEvents

CloudEvents 1.0 over HTTP in binary mode: `ce-specversion`, `ce-id` (event UUID), `ce-source` (`source`, default `https://falco.org`), `ce-type` (`falco.rule.output.v1`), `ce-time`, plus `ce-priority`, `ce-rule`, `ce-eventsource`, `ce-hostname` and the configured `extensions` (names `[a-z0-9]+`). The body is the event JSON. Not probed at startup.
