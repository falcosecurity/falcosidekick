# Amazon SNS

Publishes each event to an SNS standard topic: the output text with message attributes, or the event JSON with `raw_json: true`. `message_attributes` lists the attributes, at most 10 since raw delivery to SQS drops a message with more: `priority`, `rule`, `source`, `tags`, `hostname` and output field names, sent when the event has a string or number value (`proc.aname[2]` becomes `proc.aname.2`). Names SNS rejects and two names that become the same attribute are refused at startup, and so are FIFO topics. AWS credentials, the region, `endpoint` and the startup checks are the same for every AWS output: see [AWS credentials](common.md#aws-credentials).

Tested with LocalStack 4.14.0.

## Example

<!-- example -->
```yaml
outputs:
  awssns:
    topic_arn: arn:aws:sns:eu-west-1:123456789012:falco
    message_attributes: [priority, rule, hostname, k8s.ns.name]
```

<!-- BEGIN GENERATED: settings -->
<!-- Generated from the output schema by `make docs`. Do not edit. -->

## Settings

Key in the output file: `awssns`. Category: Queues and streams. UI event source: no. Batching: no.

| Setting | Type | Default | Description |
| --- | --- | --- | --- |
| `topic_arn` | string, **required** | - | Standard topic the events are published to, as `arn:aws:sns:REGION:ACCOUNT:NAME`; FIFO topics are refused. Its region applies when neither the region field nor the environment sets one. |
| `raw_json` | boolean | `false` | Publishes the whole event as JSON with no message attributes. Otherwise the message is the event output text, or the rule name when it is empty. |
| `message_attributes` | list of strings | `[priority rule source tags hostname]` | Event values sent as message attributes, at most 10: `priority`, `rule`, `source`, `tags`, `hostname` or output field names such as `k8s.ns.name`. Missing, empty or non-text, non-number values are left out; an empty list sends none. |

Also takes the shared settings in [AWS credentials](common.md#aws-credentials), [TLS](common.md#tls), [Delivery](common.md#delivery).

<!-- END GENERATED: settings -->
