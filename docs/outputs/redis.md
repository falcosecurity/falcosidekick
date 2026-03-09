# Redis

- **Category**: Database
- **Website**: https://redis.com/

## Table of content

- [Redis](#redis)
  - [Table of content](#table-of-content)
  - [Configuration](#configuration)
  - [Example of config.yaml](#example-of-configyaml)
  - [Additional info](#additional-info)
  - [Screenshots](#screenshots)

## Configuration

| Setting                 | Env var                 | Default value    | Description                                                                                                                         |
| ----------------------- | ----------------------- | ---------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `redis.address`         | `REDIS_ADDRESS`         |                  | Redis address, if not empty, Redis output is **enabled**                                                                            |
| `redis.database`        | `REDIS_DATABASE`        | `0`              | Redis database number                                                                                                               |
| `redis.storagetype`     | `REDIS_STORAGETYPE`     | `list`           | Redis storage type: `hashmap` or `list`                                                                                             |
| `redis.key`             | `REDIS_KEY`             | `falco`          | Redis storage key name                                                                                                              |
| `redis.username`        | N/A | | Redis user to authenticate with Redis. By default no username is set. [See ACLs for more information](https://redis.io/docs/latest/operate/oss_and_stack/management/security/acl/). |
| `redis.password`        | `REDIS_PASSWORD`        |                  | Password to authenticate with Redis                                                                                                 |
| `redis.tls`             | `REDIS_TLS`             | `false`          | Use TLS connection                                                                                                                  |
| `redis.mutualtls`       | `REDIS_MUTUALTLS`       | `false`          | Authenticate to the output with TLS; if true, checkcert is ignored (server cert will always be checked)                             |
| `redis.checkcert`       | `REDIS_CHECKCERT`       | `true`           | Check if ssl certificate of the output is valid                                                                                     |
| `redis.certfile`        | `REDIS_CERTFILE`        |                  | Client certificate file for mutual TLS                                                                                              |
| `redis.keyfile`         | `REDIS_KEYFILE`         |                  | Client key file for mutual TLS                                                                                                      |
| `redis.cacertfile`      | `REDIS_CACERTFILE`      |                  | CA certificate file for mutual TLS                                                                                                  |
| `redis.minimumpriority` | `REDIS_MINIMUMPRIORITY` | `""` (= `debug`) | Minimum priority of event for using this output, order is `emergency,alert,critical,error,warning,notice,informational,debug or ""` |

> [!NOTE]
The Env var values override the settings from yaml file.

## Example of config.yaml

```yaml
redis:
  address: "" # Redis address, if not empty, Redis output is enabled
  # database: "" # Redis database number (default: 0)
  # storagetype: "" # Redis storage type: hashmap or list (default: list)
  # key: "" # Redis storage key name (default: "falco")
  # username: "" # Username to authenticate with Redis (default: "")
  # password: "" # Password to authenticate with Redis (default: "")
  # tls: false # Use TLS connection (default: false)
  # mutualtls: false # Authenticate to the output with TLS; if true, checkcert is ignored (default: false)
  # checkcert: true # Check if ssl certificate of the output is valid (default: true)
  # certfile: "" # Client certificate file for mutual TLS (default: "")
  # keyfile: "" # Client key file for mutual TLS (default: "")
  # cacertfile: "" # CA certificate file for mutual TLS (default: "")
  # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
```

## Additional info

## Screenshots
