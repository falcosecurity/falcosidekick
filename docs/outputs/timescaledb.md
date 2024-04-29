# TimescaleDB

- **Category**: Metrics / Observability
- **Website**: https://www.timescale.com/

## Table of content

- [TimescaleDB](#timescaledb)
	- [Table of content](#table-of-content)
	- [Configuration](#configuration)
	- [Example of config.yaml](#example-of-configyaml)
	- [Additional info](#additional-info)
		- [TimescaleDB setup](#timescaledb-setup)
	- [Screenshots](#screenshots)

## Configuration

| Setting                       | Env var                       | Default value    | Description                                                                                                                         |
| ----------------------------- | ----------------------------- | ---------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `timescaledb.host`            | `TIMESCALEDB_HOST`            |                  | TimescaleDB host, if not empty, TImescaleDB output is **enabled**                                                                   |
| `timescaledb.port`            | `TIMESCALEDB_PORT`            | `5432`           | TimescaleDB port                                                                                                                    |
| `timescaledb.database`        | `TIMESCALEDB_DATABASE`        | `postgres`       | TimescaleDB database used                                                                                                           |
| `timescaledb.hypertablename`  | `TIMESCALEDB_HYPERTABLENAME`  | `falco_events`   | Hypertable to store data events, [more info](#additional-info)                                                                      |
| `timescaledb.user`            | `TIMESCALEDB_USER`            | `postgres`       | Username to authenticate with TimescaleDB                                                                                           |
| `timescaledb.password`        | `TIMESCALEDB_PASSWORD`        | `postgres`       | Password to authenticate with TimescaleDB                                                                                           |
| `timescaledb.minimumpriority` | `TIMESCALEDB_MINIMUMPRIORITY` | `""` (= `debug`) | Minimum priority of event for using this output, order is `emergency,alert,critical,error,warning,notice,informational,debug or ""` |

> [!NOTE]
The Env var values override the settings from yaml file.

## Example of config.yaml

```yaml
timescaledb:
  host: "" # TimescaleDB host, if not empty, TImescaleDB output is enabled
  port: "5432" # TimescaleDB port (default: 5432)
  database: "" # TimescaleDB database used
  hypertablename: "falco_events" # Hypertable to store data events (default: falco_events) See TimescaleDB setup for more info
  # user: "postgres" # Username to authenticate with TimescaleDB (default: postgres)
  # password: "postgres" # Password to authenticate with TimescaleDB (default: postgres)
  # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
```

## Additional info

### TimescaleDB setup

To use TimescaleDB you should create the Hypertable first, following this example

```sql
CREATE TABLE falcosidekick_events (
	time TIMESTAMPTZ NOT NULL,
	rule TEXT,
	priority VARCHAR(20),
	source VARCHAR(20),
	output TEXT,
	tags TEXT,
	hostname TEXT,
);
SELECT create_hypertable('falcosidekick_events', 'time');
```

To support [`customfields` or `templatedfields`](#yaml-file) you need to ensure you add the corresponding fields to the Hypertable, for example:

```yaml
customfields:
  custom_field_1: "custom-value-1"
templatedfields:
  k8s_namespace: '{{ or (index . "k8s.ns.name") "null" }}'
```

```sql
CREATE TABLE falcosidekick_events (
	time TIMESTAMPTZ NOT NULL,
	rule TEXT,
	priority VARCHAR(20),
	source VARCHAR(20),
	output TEXT,
	tags TEXT,
	hostname TEXT,
	custom_field_1 TEXT,
	k8s_namespace TEXT
);
SELECT create_hypertable('falcosidekick_events', 'time');
```

The name from the table should match with the `hypertable` output configuration. The TimescaleDB output processor will insert SQL nulls when it encounters a string field value of `"null"`.

## Screenshots
