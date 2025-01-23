# AWS SNS

- **Category**: Message queue / Streaming
- **Website**: https://aws.amazon.com/sns/features/

## Table of content

- [AWS SNS](#aws-sns)
  - [Table of content](#table-of-content)
  - [Configuration](#configuration)
  - [Example of config.yaml](#example-of-configyaml)
  - [Additional info](#additional-info)
    - [SNS Sample Policy](#sns-sample-policy)
  - [Screenshots](#screenshots)

## Configuration

| Setting                   | Env var                   | Default value    | Description                                                                                                                         |
| ------------------------- | ------------------------- | ---------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `aws.accesskeyid`         | `AWS_ACCESSKEYID`         |                  | AWS access key (optional if you use EC2 Instance Profile)                                                                           |
| `aws.secretaccesskey`     | `AWS_SECRETACCESSKEY`     |                  | AWS secret access key (optional if you use EC2 Instance Profile)                                                                    |
| `aws.region`              | `AWS_REGION`              |                  | AWS region (by default, the metadata are used to get it)                                                                            |
| `aws.rolearn`             | `AWS_ROLEARN`             |                  | AWS role to assume (optional if you use EC2 Instance Profile)                                                                       |
| `aws.externalid`          | `AWS_EXTERNALID`          |                  | External id for the role to assume (optional if you use EC2 Instance Profile)                                                       |
| `aws.checkidentity`       | `AWS_CHECKIDENTITY`       | `true`           | Check the identity credentials, set to false for locale developments                                                                |
| `aws.sns.topicarn`        | `AWS_SNS_TOPICARN`        |                  | SNS TopicArn, if not empty, AWS SNS output is **enabled**                                                                           |
| `aws.sns.rawjson`         | `AWS_SNS_RAWJSON`         | `false`          | end Raw JSON or parse it                                                                                                            |
| `aws.sns.minimumpriority` | `AWS_SNS_MINIMUMPRIORITY` | `""` (= `debug`) | Minimum priority of event for using this output, order is `emergency,alert,critical,error,warning,notice,informational,debug or ""` |

> [!NOTE]
The Env var values override the settings from yaml file.

## Example of config.yaml

```yaml
aws:
  # accesskeyid: "" # aws access key (optional if you use EC2 Instance Profile)
  # secretaccesskey: "" # aws secret access key (optional if you use EC2 Instance Profile)
  # region : "" # aws region (by default, the metadata are used to get it)
  # rolearn: "" # aws role to assume (optional if you use EC2 Instance Profile)
  # externalid: "" # external id for the role to assume (optional if you use EC2 Instance Profile)
  # checkidentity: true # check the identity credentials, set to false for locale developments (default: true)
  sns:
    # topicarn : "" # SNS TopicArn, if not empty, AWS SNS output is enabled
    rawjson: false # Send Raw JSON or parse it (default: false)
    # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
```

## Additional info

> [!NOTE]
When using this AWS output you will need to set the AWS keys or role with some permissions.

### SNS Sample Policy

```json
{
  "Version": "2012-10-17",
  "Id": "sns",
  "Statement": [
    {
      "Sid": "publish",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "sns:Publish",
      "Resource": "arn:aws:sqs:*:111122223333:queue1"
    }
  ]
}
```


## Screenshots
