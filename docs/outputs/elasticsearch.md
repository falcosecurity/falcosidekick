# Elasticsearch

- **Category**: Logs
- **Website**: https://www.elastic.co/elasticsearch/

## Table of content

- [Elasticsearch](#elasticsearch)
  - [Table of content](#table-of-content)
  - [Configuration](#configuration)
  - [Example of config.yaml](#example-of-configyaml)
  - [Screenshots](#screenshots)

## Configuration

|               Setting                 |               Env var                  |  Default value   |                                                             Description                                                             |
| ------------------------------------- | -------------------------------------- | ---------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `elasticsearch.hostport`              | `ELASTICSEARCH_HOSTPORT`               |                  | http://{domain or ip}:{port}, if not empty, Elasticsearch output is **enabled**                                                     |
| `elasticsearch.index`                 | `ELASTICSEARCH_INDEX`                  | `falco`          | Index                                                                                                                               |
| `elasticsearch.type`                  | `ELASTICSEARCH_TYPE`                   | `_doc`           | Index                                                                                                                               |
| `elasticsearch.pipeline`              | `ELASTICSEARCH_PIPELINE`               |                  | Optional ingest pipeline name. Documentation: https://www.elastic.co/guide/en/elasticsearch/reference/current/ingest.html           |
| `elasticsearch.suffix`                | `ELASTICSEARCH_SUFFIX`                 | `daily`          | Date suffix for index rotation : `daily`, `monthly`, `annually`, `none`                                                             |
| `elasticsearch.apikey`                | `ELASTICSEARCH_APIKEY`                 |                  | Use this APIKey to authenticate to Elasticsearch                                                                                    |
| `elasticsearch.username`              | `ELASTICSEARCH_USERNAME`               |                  | Use this username to authenticate to Elasticsearch                                                                                  |
| `elasticsearch.password`              | `ELASTICSEARCH_PASSWORD`               |                  | Use this password to authenticate to Elasticsearch                                                                                  |
| `elasticsearch.flattenfields`         | `ELASTICSEARCH_FLATTENFIELDS`          | `false`          | Replace . by _ to avoid mapping conflicts, force to true if `createindextemplate=true`                                              |
| `elasticsearch.createindextemplate`   | `ELASTICSEARCH_CREATEINDEXTEMPLATE`    | `false`          | Create an index template                                                                                                            |
| `elasticsearch.numberofshards`        | `ELASTICSEARCH_NUMBEROFSHARDS`         | `3`              | Number of shards set by the index template                                                                                          |
| `elasticsearch.numberofreplicas`      | `ELASTICSEARCH_NUMBEROFREPLICAS`       | `3`              | Number of replicas set by the index template                                                                                        |
| `elasticsearch.customheaders`         | `ELASTICSEARCH_CUSTOMHEADERS`          |                  | Custom headers to add in POST, useful for Authentication                                                                            |
| `elasticsearch.mutualtls`             | `ELASTICSEARCH_MUTUALTLS`              | `false`          | Authenticate to the output with TLS, if true, checkcert flag will be ignored (server cert will always be checked)                   |
| `elasticsearch.checkcert`             | `ELASTICSEARCH_CHECKCERT`              | `true`           | Check if ssl certificate of the output is valid                                                                                     |
| `elasticsearch.minimumpriority`       | `ELASTICSEARCH_MINIMUMPRIORITY`        | `""` (= `debug`) | Minimum priority of event for using this output, order is `emergency,alert,critical,error,warning,notice,informational,debug or ""` |
| `elasticsearch.maxconcurrentrequests` | `ELASTICSEARCH_MAXCONCURRENTREQUESTS`  | `1`              | Max number of concurrent requests                                                                                                   |
| `elasticsearch.enablecompression`     | `ELASTICSEARCH_ENABLECOMPRESSION`      | `false`          | Enables gzip compression                                                                                                            |
| `elasticsearch.batching.enabled`      | `ELASTICSEARCH_BATCHING_ENABLED`       | `false`          | Enables batching (utilizing Elasticsearch bulk API)                                                                                 |
| `elasticsearch.batching.batchsize`    | `ELASTICSEARCH_BATCHING_BATCHSIZE`     | `5242880`        | Batch size in bytes, default 5MB                                                                                                    |
| `elasticsearch.batching.flushinterval`| `ELASTICSEARCH_BATCHING_FLUSHINTERVAL` | `1s`             | Batch flush interval, use valid Go duration string                                                                                  |

> [!NOTE]
The Env var values override the settings from yaml file.

> [!NOTE]
Increasing the default number of concurrent requests is a good way to increase throughput of the http outputs. This also increases the potential number of open connections. Choose wisely.

> [!NOTE]
Enabling batching for Elasticsearch is invaluable when the expected number of falco alerts is in the hundreds or thousands per second. The batching of data can be fine-tuned for your specific use case. The batch request is sent to Elasticsearch when the pending data size reaches `batchsize` or upon the `flushinterval`.
Enabling gzip compression increases throughput even further.

> [!WARNING]
By enabling the creation of the index template with `elasticsearch.createindextemplate=true`, the output fields of the Falco events will be flatten to avoid any mapping conflict.

## Example of config.yaml

```yaml
elasticsearch:
  # hostport: "" # http://{domain or ip}:{port}, if not empty, Elasticsearch output is enabled
  # index: "falco" # index (default: falco)
  # type: "_doc"
  # suffix: "daily" # date suffix for index rotation : daily (default), monthly, annually, none
  # username: "" # use this username to authenticate to Elasticsearch if the username is not empty (default: "")
  # password: "" # use this password to authenticate to Elasticsearch if the password is not empty (default: "")
  # customHeaders: # Custom headers to add in POST, useful for Authentication
  #   key: value
  # mutualtls: false # if true, checkcert flag will be ignored (server cert will always be checked)
  # checkcert: true # check if ssl certificate of the output is valid (default: true)
  # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
  # enablecompression: # if true enables gzip compression for http requests (default: false)
  # batching: # batching configuration, improves throughput dramatically utilizing _bulk Elasticsearch API
  #   enabled: true # if true enables batching
  #   batchsize: 5242880 # batch size in bytes (default: 5 MB)
  #   flushinterval: 1s # batch fush interval (default: 1s)
  # maxconcurrentrequests: # max number of concurrent http requests (default: 1)
```

## Screenshots

With Kibana:
![kibana example](images/kibana.png)
