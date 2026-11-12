# Common settings

Settings several outputs share. Each output page says which of these it takes.

## Secrets

A secret setting never comes back from the API. Each secret string also accepts `<name>_file`, the path of a file that holds the value; with `database.backend: sqlite` or `postgres` only the file form is accepted, and a path sent through the API must be inside `api.secret_dirs` (see [configuration](../configuration.md)). Files are read when the output is built and again on reload; header and query parameter files are read at every request.

## HTTP outputs

The HTTP outputs send to `host` (scheme, host and port only) plus `base_path` and the endpoint. Only a 2xx answer counts as delivered; redirects to another origin are refused.

`HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY` apply to the HTTP outputs, the AWS outputs and OTLP `http/protobuf`, as in any Go program; requests to `localhost` and loopback addresses never use a proxy. gRPC outputs (Pub/Sub, OTLP `grpc`) follow `HTTPS_PROXY` through gRPC. Kafka, Redis, SMTP and Syslog connect directly.

## Query parameters

<!-- BEGIN GENERATED: query-params -->
<!-- Generated from the output schema by `make docs`. Do not edit. -->

| Setting | Type | Default | Description |
| --- | --- | --- | --- |
| `query_params` | map by name | - | Query parameters added to every request, by parameter name. |
| `query_params.<name>.values` | list of strings | - | Values of the query parameter, sent as written; the API returns them. |
| `query_params.<name>.secrets` | list of strings, secret | - | Values of the query parameter the API never returns. |
| `query_params.<name>.files` | list of strings, file path | - | Files whose content, without surrounding whitespace, is a value of the query parameter; read at every request. |

<!-- END GENERATED: query-params -->

## HTTP authentication and headers

Header names are case-insensitive and a name may appear once. `Authorization` set as a header must come from secrets or files, and cannot be combined with `username` or `bearer_token`.

<!-- BEGIN GENERATED: http-auth -->
<!-- Generated from the output schema by `make docs`. Do not edit. -->

| Setting | Type | Default | Description |
| --- | --- | --- | --- |
| `username` | string | - | User for HTTP basic authentication, sent with the password. |
| `password` | string, secret | - | Password for HTTP basic authentication. Also accepted as `password_file`, the path of a file holding the value. |
| `bearer_token` | string, secret | - | Token sent as `Authorization: Bearer <token>`. Also accepted as `bearer_token_file`, the path of a file holding the value. |
| `headers` | map by name | - | Extra headers sent with every request, by header name. Names are case-insensitive; headers the HTTP transport owns, such as `Host` or `Content-Length`, are refused. |
| `headers.<name>.values` | list of strings | - | Values of the header, sent as written; the API returns them. |
| `headers.<name>.secrets` | list of strings, secret | - | Values of the header the API never returns. |
| `headers.<name>.files` | list of strings, file path | - | Files whose content, without surrounding whitespace, is a value of the header; read at every request. |

<!-- END GENERATED: http-auth -->

## AWS credentials

- Credentials: static keys when set, otherwise the AWS SDK default chain (environment, shared files, EKS IRSA and Pod Identity, ECS and EC2 roles); `role_arn` is then assumed through STS. Instance metadata is not used to find the region.
- `endpoint` replaces the service endpoint (LocalStack, S3-compatible stores, VPC endpoints). `tls` applies to that service only; the credential calls (STS for `role_arn`, IRSA, profiles) trust the system CAs. Each call is attempted once and bounded to 30s; the pipeline retries.
- The output starts degraded, with the reason, when AWS rejects the credentials, STS refuses `role_arn`, or the bucket, queue or topic does not exist. The probe reads the resource (`s3:ListBucket`, `sqs:GetQueueAttributes`, `sns:GetTopicAttributes`); without that permission the output starts degraded too.
- AWS errors follow the SDK's retry rules, not the HTTP status: throttling answered with HTTP 400 is retried.

<!-- BEGIN GENERATED: aws -->
<!-- Generated from the output schema by `make docs`. Do not edit. -->

| Setting | Type | Default | Description |
| --- | --- | --- | --- |
| `region` | string | - | AWS region, such as `eu-west-1`. Empty takes it from the environment (`AWS_REGION`); SNS and SQS then use the region of the topic ARN or the queue URL, while S3 has no fallback and needs one. |
| `access_key_id` | string, secret | - | Static access key, set with the secret access key. Empty uses the default credential chain: environment, shared files, web identity or instance role. Also accepted as `access_key_id_file`, the path of a file holding the value. |
| `secret_access_key` | string, secret | - | Secret of the static access key. Also accepted as `secret_access_key_file`, the path of a file holding the value. |
| `session_token` | string, secret | - | Session token of temporary static credentials; needs the access key and its secret. Also accepted as `session_token_file`, the path of a file holding the value. |
| `role_arn` | string | - | IAM role assumed with the credentials above, as `arn:aws:iam::ACCOUNT:role/NAME`. |
| `external_id` | string | - | External ID the role's trust policy requires. |
| `endpoint` | string | - | Service address that replaces the AWS one, such as a LocalStack or VPC endpoint, as scheme, host and port. |

<!-- END GENERATED: aws -->

## TLS

TLS 1.2 is the minimum version.

<!-- BEGIN GENERATED: tls -->
<!-- Generated from the output schema by `make docs`. Do not edit. -->

| Setting | Type | Default | Description |
| --- | --- | --- | --- |
| `tls.insecure_skip_verify` | boolean | `false` | Accepts any server certificate. The connection can then be intercepted: use it only for tests. |
| `tls.ca_file` | string, file path | - | PEM file with the certificate authorities that sign the server certificate. Empty uses the system trust store. |
| `tls.cert_file` | string, file path | - | PEM client certificate for mutual TLS, set together with the key file. |
| `tls.key_file` | string, file path | - | PEM private key of the client certificate. |
| `tls.server_name` | string | - | Name checked against the server certificate when it differs from the host the output connects to. |

<!-- END GENERATED: tls -->

## Delivery

The `runtime:` settings of an output. The defaults below are the built-in ones: `runtime_defaults` in the core configuration replaces them for every output, and an output's own `runtime:` replaces those.

An omitted or `null` setting uses the default; an explicit `0` is refused where a positive value is required; `""` on a setting with a default uses the default. `workers` × `batch_size` is at most 100000 when batching is on. The ranges are in [configuration](../configuration.md#output-runtime).

<!-- BEGIN GENERATED: delivery -->
<!-- Generated from the output schema by `make docs`. Do not edit. -->

| Setting | Type | Default | Description |
| --- | --- | --- | --- |
| `runtime.minimum_priority` | one of `debug`, `informational`, `notice`, `warning`, `error`, `critical`, `alert`, `emergency` | - | Events below this priority are not sent to this output. Empty sends every priority. |
| `runtime.queue_size` | integer | `1000` | Events this output holds while they wait for delivery. When the queue is full, new events for this output are dropped and counted as dropped. |
| `runtime.workers` | integer | `2` | Deliveries this output runs at the same time. |
| `runtime.retry.max_attempts` | integer | `3` | Delivery attempts per event, the first one included. A permanent error, such as rejected credentials, is not retried. |
| `runtime.retry.initial_interval` | string | `1s` | Wait before the second attempt, as a duration such as `500ms` or `2s`. |
| `runtime.retry.max_interval` | string | `30s` | Longest wait between two attempts, as a duration. |
| `runtime.retry.multiplier` | number | `2` | Factor applied to the wait after each failed attempt, up to the longest wait. |
| `runtime.circuit_breaker.failure_threshold` | integer | `5` | Consecutive failed deliveries that open the circuit. While it is open the output sends nothing and new events wait in the queue. |
| `runtime.circuit_breaker.success_threshold` | integer | `2` | Successful deliveries in a row that close the circuit again after the reset timeout. |
| `runtime.circuit_breaker.reset_timeout` | string | `30s` | Time the circuit stays open before a trial delivery, as a duration. |
| `runtime.health_check` | boolean | `true` | Checks the destination at startup, on reload and on API changes, for up to 5 seconds. A failure, such as rejected credentials or a missing resource, does not refuse the configuration: the output starts degraded with the reason in its status and delivers once the destination accepts. |

<!-- END GENERATED: delivery -->

## Batching

Only the outputs that send events in groups take these settings; the [index](README.md) lists them.

<!-- BEGIN GENERATED: batching -->
<!-- Generated from the output schema by `make docs`. Do not edit. -->

| Setting | Type | Default | Description |
| --- | --- | --- | --- |
| `runtime.batching.enabled` | boolean | `false` | Sends events in groups, one request per group. |
| `runtime.batching.batch_size` | integer | `500` | Most events in one group. |
| `runtime.batching.flush_interval` | string | `1s` | Longest time an incomplete group waits before it is sent, as a duration. |

<!-- END GENERATED: batching -->
