# Amazon SQS

Sends each event as a message to an SQS standard queue. Batches go out with `SendMessageBatch`, 10 messages and 1 MiB per request; every request is sent and the batch fails when any message fails. It fails for good only when every failed entry is a sender fault. FIFO queues are refused at startup: they need a message group the output does not set. AWS credentials, the region, `endpoint` and the startup checks are the same for every AWS output: see [AWS credentials](common.md#aws-credentials).

Tested with LocalStack 4.14.0.

## Example

<!-- example -->
```yaml
outputs:
  awssqs:
    queue_url: https://sqs.eu-west-1.amazonaws.com/123456789012/falco
```

<!-- BEGIN GENERATED: settings -->
<!-- Generated from the output schema by `make docs`. Do not edit. -->

## Settings

Key in the output file: `awssqs`. Category: Queues and streams. UI event source: no. Batching: yes.

| Setting | Type | Default | Description |
| --- | --- | --- | --- |
| `queue_url` | string, **required** | - | URL of a standard queue, such as `https://sqs.eu-west-1.amazonaws.com/123456789012/falco`; FIFO queues are refused. Its region applies when neither the region field nor the environment sets one. |

Also takes the shared settings in [AWS credentials](common.md#aws-credentials), [TLS](common.md#tls), [Delivery](common.md#delivery), [Batching](common.md#batching).

<!-- END GENERATED: settings -->
