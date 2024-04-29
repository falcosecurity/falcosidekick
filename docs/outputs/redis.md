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
| `redis.password`        | `REDIS_PASSWORD`        |                  | Password to authenticate with Redis                                                                                                 |
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
  # password: "" # Password to authenticate with Redis (default: "")
  # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
```

## Additional info

## Screenshots
