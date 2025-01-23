# AWS Cloudwatch Logs

- **Category**: Logs
- **Website**: https://aws.amazon.com/cloudwatch/features/

## Table of content

- [AWS Cloudwatch Logs](#aws-cloudwatch-logs)
  - [Table of content](#table-of-content)
  - [Configuration](#configuration)
  - [Example of config.yaml](#example-of-configyaml)
  - [Additional info](#additional-info)
    - [CloudWatch Logs Sample IAM Policy](#cloudwatch-logs-sample-iam-policy)
  - [Screenshots](#screenshots)

## Configuration

| Setting                              | Env var                              | Default value    | Description                                                                                                                         |
| ------------------------------------ | ------------------------------------ | ---------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `aws.accesskeyid`                    | `AWS_ACCESSKEYID`                    |                  | AWS access key (optional if you use EC2 Instance Profile)                                                                           |
| `aws.secretaccesskey`                | `AWS_SECRETACCESSKEY`                |                  | AWS secret access key (optional if you use EC2 Instance Profile)                                                                    |
| `aws.region`                         | `AWS_REGION`                         |                  | AWS region (by default, the metadata are used to get it)                                                                            |
| `aws.rolearn`                        | `AWS_ROLEARN`                        |                  | AWS role to assume (optional if you use EC2 Instance Profile)                                                                       |
| `aws.externalid`                     | `AWS_EXTERNALID`                     |                  | External id for the role to assume (optional if you use EC2 Instance Profile)                                                       |
| `aws.checkidentity`                  | `AWS_CHECKIDENTITY`                  | `true`           | Check the identity credentials, set to false for locale developments                                                                |
| `aws.cloudwatchlogs.loggroup`        | `AWS_CLOUDWATCHLOGS_LOGGROUP`        |                  | AWS CloudWatch Logs Group name, if not empty, CloudWatch Logs output is **enabled**                                                 |
| `aws.cloudwatchlogs.logstream`       | `AWS_CLOUDWATCHLOGS_LOGSTREAM`       |                  | AWS CloudWatch Logs Stream name, if empty, Falcosidekick will try to create a log stream                                            |
| `aws.cloudwatchlogs.minimumpriority` | `AWS_CLOUDWATCHLOGS_MINIMUMPRIORITY` | `""` (= `debug`) | Minimum priority of event for using this output, order is `emergency,alert,critical,error,warning,notice,informational,debug or ""` |


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
  cloudwatchlogs:
    loggroup : "" #  AWS CloudWatch Logs Group name, if not empty, CloudWatch Logs output is enabled
    logstream : "" # AWS CloudWatch Logs Stream name, if empty, Falcosidekick will try to create a log stream
    # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
```

## Additional info

> [!NOTE]
When using this AWS output you will need to set the AWS keys or role with some permissions.

### CloudWatch Logs Sample IAM Policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "cloudwacthlogs",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogStream",
        "logs:DescribeLogStreams",
        "logs:PutRetentionPolicy",
        "logs:PutLogEvents"
      ],
      "Resource": "*"
    }
  ]
}
```

## Screenshots
