# AWS Security Lake

- **Category**: SIEM
- **Website**: https://aws.amazon.com/security-lake/

## Table of content

- [AWS Security Lake](#aws-security-lake)
  - [Table of content](#table-of-content)
  - [Configuration](#configuration)
  - [Example of config.yaml](#example-of-configyaml)
  - [Additional info](#additional-info)
  - [Screenshots](#screenshots)

## Configuration

| Setting                            | Env var                            | Default value    | Description                                                                                                                         |
| ---------------------------------- | ---------------------------------- | ---------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `aws.accesskeyid`                  | `AWS_ACCESSKEYID`                  |                  | AWS access key (optional if you use EC2 Instance Profile)                                                                           |
| `aws.secretaccesskey`              | `AWS_SECRETACCESSKEY`              |                  | AWS secret access key (optional if you use EC2 Instance Profile)                                                                    |
| `aws.region`                       | `AWS_REGION`                       |                  | AWS region (by default, the metadata are used to get it)                                                                            |
| `aws.rolearn`                      | `AWS_ROLEARN`                      |                  | AWS role to assume (optional if you use EC2 Instance Profile)                                                                       |
| `aws.externalid`                   | `AWS_EXTERNALID`                   |                  | External id for the role to assume (optional if you use EC2 Instance Profile)                                                       |
| `aws.checkidentity`                | `AWS_CHECKIDENTITY`                | `true`           | Check the identity credentials, set to false for locale developments                                                                |
| `aws.securitylake.bucket`          | `AWS_SECURITYLAKE_BUCKET`          |                  | Bucket for AWS SecurityLake data, if not empty, AWS SecurityLake output is **enabled**                                              |
| `aws.securitylake.region`          | `AWS_SECURITYLAKE_REGION`          |                  | Bucket Region for AWS SecurityLake data                                                                                             |
| `aws.securitylake.prefix`          | `AWS_SECURITYLAKE_PREFIX`          |                  | Prefix for keys                                                                                                                     |
| `aws.securitylake.accountid`       | `AWS_SECURITYLAKE_ACCOUNTID`       |                  | Account ID                                                                                                                          |
| `aws.securitylake.interval`        | `AWS_SECURITYLAKE_INTERVAL`        | `5`              | Time in minutes between two puts to S3 (must be between 5 and 60min)                                                                |
| `aws.securitylake.batchsize`       | `AWS_SECURITYLAKE_BATCHSIZE`       | `1000`           | Max number of events by parquet file                                                                                                |
| `aws.securitylake.minimumpriority` | `AWS_SECURITYLAKE_MINIMUMPRIORITY` | `""` (= `debug`) | Minimum priority of event for using this output, order is `emergency,alert,critical,error,warning,notice,informational,debug or ""` |

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
  securitylake.:
    bucket: "" # Bucket for AWS SecurityLake data, if not empty, AWS SecurityLake output is enabled
    region: "" # Bucket Region
    prefix: "" # Prefix for keys
    accountid: "" # Account ID
    # interval: 5 # Time in minutes between two puts to S3 (must be between 5 and 60min) (default: 5min)
    # batchsize: 1000 # Max number of events by parquet file (default: 1000)
    # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
```

## Additional info

> [!NOTE]
When using this AWS output you will need to set the AWS keys or role with some permissions.

## Screenshots
