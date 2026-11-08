# Amazon S3

Writes each event to an S3 bucket, one object per event, `<prefix>/<YYYY-MM-DD>/<event time>_<uuid>.json`, or one NDJSON object per batch; without a prefix the keys start at the date. A retry overwrites the same key. AWS credentials, the region, `endpoint` and the startup checks are the same for every AWS output: see [AWS credentials](common.md#aws-credentials).

S3 answers a bucket check with a bare 403 both for a missing permission and for a bucket of another account, so both start degraded.

Tested with LocalStack 4.14.0.

## Example

<!-- example -->
```yaml
outputs:
  awss3:
    region: eu-west-1
    bucket: falco-events
    prefix: falco
```

<!-- BEGIN GENERATED: settings -->
<!-- Generated from the output schema by `make docs`. Do not edit. -->

## Settings

Key in the output file: `awss3`. Category: Storage. UI event source: no. Batching: yes.

| Setting | Type | Default | Description |
| --- | --- | --- | --- |
| `bucket` | string, **required** | - | Name of the bucket the events are written to, 3 to 63 lowercase letters, digits, `.` or `-`. |
| `prefix` | string | - | Start of every object key, followed by `/YYYY-MM-DD/<event time>_<event id>.json`, or `.ndjson` for a batch. Leading and trailing `/` are removed; empty writes the keys from the date, at the root of the bucket. Suggested: `falco`. |
| `object_canned_acl` | one of `private`, `public-read`, `public-read-write`, `authenticated-read`, `aws-exec-read`, `bucket-owner-read`, `bucket-owner-full-control` | `bucket-owner-full-control` | Canned ACL set on every object written. |
| `use_path_style` | boolean | `false` | Addresses the bucket in the path, as `https://host/bucket/key`, instead of in the host name; S3-compatible stores such as MinIO often need it. |

Also takes the shared settings in [AWS credentials](common.md#aws-credentials), [TLS](common.md#tls), [Delivery](common.md#delivery), [Batching](common.md#batching).

<!-- END GENERATED: settings -->
