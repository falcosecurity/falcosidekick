# NATS

- **Category**: Message queue / Streaming
- **Website**: https://nats.io/

## Table of content

- [NATS](#nats)
  - [Table of content](#table-of-content)
  - [Configuration](#configuration)
  - [subjecttemplate: "falco.." # template for the subject, tokens  and  will be automatically replaced (default: falco..)](#subjecttemplate-falco--template-for-the-subject-tokens--and--will-be-automatically-replaced-default-falco)
  - [Example of `config.yaml`](#example-of-configyaml)
  - [Additional info](#additional-info)
  - [Screenshots](#screenshots)

## Configuration

| Setting                | Env var                | Default value            | Description                                                                                                                              |
| ---------------------- | ---------------------- | ------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `nats.hostport`        | `NATS_HOSTPORT`        |                          | `nats://{domain or ip}:{port}`, if not empty, NATS output is **enabled**                                                                |
| `nats.subjecttemplate` | `NATS_SUBJECTTEMPLATE` | `falco.<priority>.<rule>`| Template for the subject, tokens `<priority>` and `<rule>` will be automatically replaced                                               |
| `nats.credsfile`       | `NATS_CREDSFILE`       | `""`                     | Path to a NATS `.creds` file. This option cannot be combined with `nats.nkeyseedfile` or `nats.jwtfile`                               |
| `nats.nkeyseedfile`    | `NATS_NKEYSEEDFILE`    | `""`                     | Path to a NATS NKey seed file. Can be used alone (NKey auth) or with `nats.jwtfile` (JWT auth)                                         |
| `nats.jwtfile`         | `NATS_JWTFILE`         | `""`                     | Path to a NATS JWT file. Requires `nats.nkeyseedfile`                                                                                    |
| `nats.mutualtls`       | `NATS_MUTUALTLS`       | `false`                  | Authenticate to the output with TLS, if true, `checkcert` is ignored (server cert will always be checked)                              |
| `nats.checkcert`       | `NATS_CHECKCERT`       | `true`                   | Check if SSL certificate of the output is valid                                                                                          |
| `nats.minimumpriority` | `NATS_MINIMUMPRIORITY` | `""` (= `debug`)         | Minimum priority of event for using this output, order is `emergency,alert,critical,error,warning,notice,informational,debug or ""`   |

> [!NOTE]
> Env var values override settings from `config.yaml`.

<a id="subjecttemplate-falco--template-for-the-subject-tokens--and--will-be-automatically-replaced-default-falco"></a>

### `subjecttemplate: "falco.<priority>.<rule>" # template for the subject, tokens <priority> and <rule> will be automatically replaced (default: falco.<priority>.<rule>)`

- Subject tokens:
  - `<priority>`: Falco priority (`debug`, `notice`, `warning`, ...)
  - `<rule>`: Falco rule name normalized for subjects
- Example result:
  - Template: `falco.<priority>.<rule>`
  - Event: priority `Debug`, rule `Test rule`
  - Subject: `falco.debug.test_rule`

## Example of `config.yaml`

```yaml
nats:
  hostport: "" # nats://{domain or ip}:{port}, if not empty, NATS output is enabled
  # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
  # subjecttemplate: "falco.<priority>.<rule>" # template for the subject, tokens <priority> and <rule> will be automatically replaced (default: falco.<priority>.<rule>)
  # mutualtls: false # if true, checkcert flag will be ignored (server cert will always be checked)
  # checkcert: true # check if ssl certificate of the output is valid (default: true)
  # credsfile: "" # path to NATS .creds file (exclusive with jwtfile/nkeyseedfile)
  # nkeyseedfile: "" # path to NATS NKey seed file (alone for NKey auth, or with jwtfile for JWT auth)
  # jwtfile: "" # path to NATS JWT file (requires nkeyseedfile)
```

## Additional info

- Supported auth combinations:
  - `.creds` mode: set `nats.credsfile` only
  - NKey mode: set `nats.nkeyseedfile` only
  - JWT mode: set both `nats.jwtfile` and `nats.nkeyseedfile`
- Invalid combinations are rejected at startup and NATS output is disabled.

## Screenshots

No dedicated screenshot for NATS output yet.
