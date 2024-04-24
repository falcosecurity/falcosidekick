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

| Setting                         | Env var                         | Default value    | Description                                                                                                                         |
| ------------------------------- | ------------------------------- | ---------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `elasticsearch.hosport`         | `ELASTICSEARCH_HOSTPORT`        |                  | http://{domain or ip}:{port}, if not empty, Elasticsearch output is **enabled**                                                     |
| `elasticsearch.index`           | `ELASTICSEARCH_INDEX`           | `falco`          | Index                                                                                                                               |
| `elasticsearch.type`            | `ELASTICSEARCH_TYPE`            | `_doc`           | Index                                                                                                                               |
| `elasticsearch.suffix`          | `ELASTICSEARCH_SUFFIX`          | `daily`          | Date suffix for index rotation : `daily`, `monthly`, `annually`, `none`                                                             |
| `elasticsearch.username`        | `ELASTICSEARCH_USERNAME`        |                  | Use this username to authenticate to Elasticsearch                                                                                  |
| `elasticsearch.password`        | `ELASTICSEARCH_PASSWORD`        |                  | Use this password to authenticate to Elasticsearch                                                                                  |
| `elasticsearch.customheaders`   | `ELASTICSEARCH_CUSTOMHEADERS`   |                  | Custom headers to add in POST, useful for Authentication                                                                            |
| `elasticsearch.mutualtls`       | `ELASTICSEARCH_MUTUALTLS`       | `false`          | Authenticate to the output with TLS, if true, checkcert flag will be ignored (server cert will always be checked)                   |
| `elasticsearch.checkcert`       | `ELASTICSEARCH_CHECKCERT`       | `true`           | Check if ssl certificate of the output is valid                                                                                     |
| `elasticsearch.minimumpriority` | `ELASTICSEARCH_MINIMUMPRIORITY` | `""` (= `debug`) | Minimum priority of event for using this output, order is `emergency,alert,critical,error,warning,notice,informational,debug or ""` |

> [!NOTE]
The Env var values override the settings from yaml file.

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
```

## Screenshots

With Kibana:
![kibana example](images/kibana.png)
