# AWS S3

- **Category**: Object storage
- **Website**: https://aws.amazon.com/s3/features/

## Table of content

- [AWS S3](#aws-s3)
  - [Table of content](#table-of-content)
  - [Configuration](#configuration)
  - [Example of config.yaml](#example-of-configyaml)
  - [Additional info](#additional-info)
  - [Screenshots](#screenshots)

## Configuration

| Setting                  | Env var                  | Default value               | Description                                                                                                                         |
|--------------------------|--------------------------|-----------------------------|-------------------------------------------------------------------------------------------------------------------------------------|
| `aws.accesskeyid`        | `AWS_ACCESSKEYID`        |                             | AWS access key (optional if you use EC2 Instance Profile)                                                                           |
| `aws.secretaccesskey`    | `AWS_SECRETACCESSKEY`    |                             | AWS secret access key (optional if you use EC2 Instance Profile)                                                                    |
| `aws.region`             | `AWS_REGION`             |                             | AWS region (by default, the metadata are used to get it)                                                                            |
| `aws.rolearn`            | `AWS_ROLEARN`            |                             | AWS role to assume (optional if you use EC2 Instance Profile)                                                                       |
| `aws.externalid`         | `AWS_EXTERNALID`         |                             | External id for the role to assume (optional if you use EC2 Instance Profile)                                                       |
| `aws.checkidentity`      | `AWS_checkidentity`      | `true`                      | Check the identity credentials, set to false for locale developments                                                                |
| `aws.s3.bucket`          | `AWS_S3_BUCKET`          |                             | AWS S3 bucket name, if not empty, AWS S3 output is **enabled**                                                                      |
| `aws.s3.prefix`          | `AWS_S3_PREFIX`          |                             | Prefix, keys will have format: s3://<bucket>/<prefix>/YYYY-MM-DD/YYYY-MM-DDTHH:mm:ss.s+01:00.json                                   |
| `aws.s3.minimumpriority` | `AWS_S3_MINIMUMPRIORITY` | `""` (= `debug`)            | Minimum priority of event for using this output, order is `emergency,alert,critical,error,warning,notice,informational,debug or ""` |
| `aws.s3.endpoint`        | `AWS_S3_ENDPOINT`        |                             | Endpoint URL that overrides the default generated endpoint, use this for S3 compatible APIs                                         |
| `aws.s3.objectcannedacl` | `AWS_S3_OBJECTCANNEDACL` | `bucket-owner-full-control` | Canned ACL (`x-amz-acl`) to use when creating the object                                                                            |

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
  s3:
    bucket: "falcosidekick" # AWS S3, bucket name
    prefix : "" # Prefix, keys will have format: s3://<bucket>/<prefix>/YYYY-MM-DD/YYYY-MM-DDTHH:mm:ss.s+01:00.json
    # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
    # endpoint: "" # endpoint URL that overrides the default generated endpoint, use this for S3 compatible APIs
    # objectcannedacl: "bucket-owner-full-control" # Canned ACL (x-amz-acl) to use when creating the object
```

## Additional info

> [!NOTE]
When using this AWS output you will need to set the AWS keys or role with some permissions.

## Screenshots
