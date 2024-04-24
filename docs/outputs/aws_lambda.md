# AWS Lambda

- **Category**: FaaS / Serverless
- **Website**: https://aws.amazon.com/lambda/features/

## Table of content

- [AWS Lambda](#aws-lambda)
  - [Table of content](#table-of-content)
  - [Configuration](#configuration)
  - [Example of config.yaml](#example-of-configyaml)
  - [Additional info](#additional-info)
    - [Lambda Sample IAM Policy](#lambda-sample-iam-policy)
  - [Screenshots](#screenshots)

## Configuration

| Setting                      | Env var                      | Default value    | Description                                                                                                                         |
| ---------------------------- | ---------------------------- | ---------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `aws.accesskeyid`            | `AWS_ACCESSKEYID`            |                  | AWS access key (optional if you use EC2 Instance Profile)                                                                           |
| `aws.secretaccesskey`        | `AWS_SECRETACCESSKEY`        |                  | AWS secret access key (optional if you use EC2 Instance Profile)                                                                    |
| `aws.region`                 | `AWS_REGION`                 |                  | AWS region (by default, the metadata are used to get it)                                                                            |
| `aws.rolearn`                | `AWS_ROLEARN`                |                  | AWS role to assume (optional if you use EC2 Instance Profile)                                                                       |
| `aws.externalid`             | `AWS_EXTERNALID`             |                  | External id for the role to assume (optional if you use EC2 Instance Profile)                                                       |
| `aws.checkidentity`          | `AWS_checkidentity`          | `true`           | Check the identity credentials, set to false for locale developments                                                                |
| `aws.lambda.functionname`    | `AWS_LAMBDA_FUNCTIONNAME`    |                  | Lambda function name, if not empty, AWS Lambda output is **enabled**                                                                |
| `aws.lambda.minimumpriority` | `AWS_LAMBDA_MINIMUMPRIORITY` | `""` (= `debug`) | Minimum priority of event for using this output, order is `emergency,alert,critical,error,warning,notice,informational,debug or ""` |

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
  lambda:
    functionname : "" # Lambda function name, if not empty, AWS Lambda output is enabled
    # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
```

## Additional info

> [!NOTE]
When using this AWS output you will need to set the AWS keys or role with some permissions.

### Lambda Sample IAM Policy

```json
{
  "Version": "2012-10-17",
  "Id": "lambda",
  "Statement": [
    {
      "Sid": "invoke",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "lambda:InvokeFunction",
      "Resource": "*"
    }
  ]
}
```

## Screenshots
