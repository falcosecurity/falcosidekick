# Outputs

Each output has a page with what it does, an example and its settings. Settings several outputs share are in [common settings](common.md). Outputs are configured in output files (`-o outputs.yaml`, under `outputs:`), or from the UI and the API when writes are allowed.

The settings tables are generated from the schema the code defines, the same one the API serves at `/api/v1/pipeline/outputs/types`; `make docs` updates them.

<!-- BEGIN GENERATED: index -->
<!-- Generated from the output schema by `make docs`. Do not edit. -->

| Output | Key | Category | UI event source | Batching |
| --- | --- | --- | --- | --- |
| [Alertmanager](alertmanager.md) | `alertmanager` | Alerting and on-call | no | no |
| [Amazon S3](awss3.md) | `awss3` | Storage | no | yes |
| [Amazon SNS](awssns.md) | `awssns` | Queues and streams | no | no |
| [Amazon SQS](awssqs.md) | `awssqs` | Queues and streams | no | yes |
| [CloudEvents](cloudevents.md) | `cloudevents` | Webhooks | no | no |
| [Datadog](datadog.md) | `datadog` | Alerting and on-call | no | no |
| [Discord](discord.md) | `discord` | Chat | no | no |
| [Elasticsearch](elasticsearch.md) | `elasticsearch` | Logs | no | yes |
| [Google Pub/Sub](gcppubsub.md) | `gcppubsub` | Queues and streams | no | yes |
| [Grafana OnCall](grafanaoncall.md) | `grafanaoncall` | Alerting and on-call | no | no |
| [In-memory store](inmemory.md) | `inmemory` | Storage | yes | no |
| [Apache Kafka](kafka.md) | `kafka` | Queues and streams | no | yes |
| [Loki](loki.md) | `loki` | Logs | no | yes |
| [Opsgenie](opsgenie.md) | `opsgenie` | Alerting and on-call | no | no |
| [OpenTelemetry (OTLP)](otlp.md) | `otlp` | Observability | no | yes |
| [PagerDuty](pagerduty.md) | `pagerduty` | Alerting and on-call | no | no |
| [Policy Report](policyreport.md) | `policyreport` | Other | no | yes |
| [Redis](redis.md) | `redis` | Storage | no | yes |
| [Slack](slack.md) | `slack` | Chat | no | no |
| [Email (SMTP)](smtp.md) | `smtp` | Email | no | no |
| [Syslog](syslog.md) | `syslog` | Logs | no | no |
| [Falco Talon](talon.md) | `talon` | Response | no | no |
| [Microsoft Teams](teams.md) | `teams` | Chat | no | no |
| [Webhook](webhook.md) | `webhook` | Webhooks | no | no |

<!-- END GENERATED: index -->
