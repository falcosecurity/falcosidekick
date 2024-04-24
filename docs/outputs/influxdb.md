# InfluxDB


- **Category**: Metrics/Observability
- **Website**: https://www.influxdata.com/products/influxdb/

## Table of content

- [InfluxDB](#influxdb)
  - [Table of content](#table-of-content)
  - [Configuration](#configuration)
  - [Example of config.yaml](#example-of-configyaml)
  - [Result](#result)

## Configuration

| Setting                    | Env var                    | Default value    | Description                                                                                                                         |
| -------------------------- | -------------------------- | ---------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `influxdb.hostport`        | `INFLUXDB_HOSTPORT`        |                  | http://{domain or ip}:{port}, if not empty, Influxdb output is **enabled**                                                          |
| `influxdb.database`        | `INFLUXDB_DATABASE`        | `falco`          | Influxdb database (api v1 only)                                                                                                     |
| `influxdb.organization`    | `INFLUXDB_ORGANISATION`    |                  | Influxdb organisation                                                                                                               |
| `influxdb.bucket`          | `INFLUXDB_BUCKET`          | `falco`          | Metrics bucket                                                                                                                      |
| `influxdb.precision`       | `INFLUXDB_PRECISION`       | `ns`             | Write precision                                                                                                                     |
| `influxdb.user`            | `INFLUXDB_USER`            |                  | User to use if auth is enabled in Influxdb                                                                                          |
| `influxdb.password`        | `INFLUXDB_PASSWORD`        |                  | Password to use if auth is enabled in Influxdb                                                                                      |
| `influxdb.token`           | `INFLUXDB_TOKEN`           |                  | API token to use if auth in enabled in Influxdb (disables user and password)                                                        |
| `influxdb.mutualtls`       | `INFLUXDB_MUTUALTLS`       | `false`          | Authenticate to the output with TLS, if true, checkcert flag will be ignored (server cert will always be checked)                   |
| `influxdb.checkcert`       | `INFLUXDB_CHECKCERT`       | `true` | Check if ssl certificate of the output is valid                                                                                     | `mattermost.minimumpriority` | `MATTERMOST_MINIMUMPRIORITY` | `""` (= `debug`)                                                                                    | Minimum priority of event for using this output, order is `emergency,alert,critical,error,warning,notice,informational,debug or ""`
| `influxdb.minimumpriority` | `INFLUXDB_MINIMUMPRIORITY` | `""` (= `debug`) | Minimum priority of event for using this output, order is `emergency,alert,critical,error,warning,notice,informational,debug or ""` |

> [!NOTE]
The Env var values override the settings from yaml file.

## Example of config.yaml

```yaml
influxdb:
  # hostport: "" # http://{domain or ip}:{port}, if not empty, Influxdb output is enabled
  # database: "falco" # Influxdb database (api v1 only) (default: falco)
  # organization: "" # Influxdb organization
  # bucket: "falco" # Metrics bucket (default: falco)
  # precision: "ns" # Write precision
  # user: "" # user to use if auth is enabled in Influxdb
  # password: "" # pasword to use if auth is enabled in Influxdb
  # token: "" # API token to use if auth in enabled in Influxdb (disables user and password)
  # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
  # mutualtls: false # if true, checkcert flag will be ignored (server cert will always be checked)
  # checkcert: true # check if ssl certificate of the output is valid (default: true)
```

## Result

```bash
> use falco
Using database falco
> show series
key
---
events,akey=AValue,bkey=BValue,ckey=CValue,priority=Debug,rule=Testrule
events,akey=A_Value,bkey=B_Value,ckey=C_Value,priority=Debug,rule=Test_rule
> select * from events
name: events
time                akey    bkey    ckey    priority rule      value
----                ----    ----    ----    -------- ----      -----
1560433816893368400 AValue  BValue  CValue  Debug    Testrule  This is a test from falcosidekick
1560441359119741800 A_Value B_Value C_Value Debug    Test_rule This is a test from falcosidekick
```