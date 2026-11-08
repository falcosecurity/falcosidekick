# Google Pub/Sub

Publishes the event JSON to `topic` in `project_id`, with `custom_attributes` as message attributes.

- Without `credentials` the output uses Application Default Credentials, which covers GKE Workload Identity.
- Through the API, inline `credentials` with a `credential_source` (Workload Identity Federation) are refused, since the library would read the file or URL it names and send it to the document's `token_url`; set them in an output file or as `credentials_file` inside `api.secret_dirs`.
- Startup reads the topic: a missing topic or rejected credentials stop startup; without `pubsub.topics.get` the output starts degraded.
- `emulator_host` targets the emulator without TLS or authentication. The `PUBSUB_EMULATOR_HOST` environment variable, when set in the process, overrides the client for every Pub/Sub output.
- Each publish is one request with no client-side buffering or retry, bounded at 30s; a batch is split into requests of at most 1000 messages and 10 MB, counted as encoded. Every request is sent even when an earlier one fails; a failed request fails the batch, so a retry can publish again the messages other requests delivered.
- A failed TLS handshake is retried, and at startup it leaves the output degraded: gRPC reports an untrusted certificate and a connection reset during the handshake the same way.
- gRPC follows `HTTPS_PROXY`.

Tested with the emulator from google-cloud-cli 592.0.0.

## Example

<!-- example -->
```yaml
outputs:
  gcppubsub:
    project_id: my-project
    topic: falco-events
    credentials_file: /etc/falcosidekick/secrets/gcppubsub/credentials.json
```

<!-- BEGIN GENERATED: settings -->
<!-- Generated from the output schema by `make docs`. Do not edit. -->

## Settings

Key in the output file: `gcppubsub`. Category: Queues and streams. UI event source: no. Batching: yes.

| Setting | Type | Default | Description |
| --- | --- | --- | --- |
| `project_id` | string, **required** | - | ID of the Google Cloud project that owns the topic, such as `my-project`, not its name or number path. |
| `topic` | string, **required** | - | ID of the topic within the project, not its full `projects/.../topics/...` name: 3 to 255 characters starting with a letter, not with `goog`. |
| `credentials` | string, secret | - | Google credentials JSON, raw or base64-encoded, of type `service_account`, `authorized_user`, `impersonated_service_account` or `external_account`. Empty uses Application Default Credentials. Also accepted as `credentials_file`, the path of a file holding the value. |
| `custom_attributes` | map by name | - | Attributes set on every message, by name; at most 100, names up to 256 bytes not starting with `goog`, values up to 1024 bytes. |
| `endpoint` | string | - | Pub/Sub service address as `host:port` without a scheme, such as a regional or private endpoint, reached over TLS. Empty uses the global Google endpoint. |
| `emulator_host` | string | - | Address of a Pub/Sub emulator as `host:port`, reached in plaintext without authentication; cannot be combined with the endpoint or credentials. |

Also takes the shared settings in [Delivery](common.md#delivery), [Batching](common.md#batching).

<!-- END GENERATED: settings -->
