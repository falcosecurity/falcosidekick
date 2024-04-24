# Spyderbat

- **Category**: Metrics / Observability
- **Website**: https://www.spyderbat.com/

## Table of content

- [Spyderbat](#spyderbat)
  - [Table of content](#table-of-content)
  - [Configuration](#configuration)
  - [Example of config.yaml](#example-of-configyaml)
  - [Additional info](#additional-info)
  - [Screenshots](#screenshots)

## Configuration

| Setting                       | Env var                       | Default value               | Description                                                                                                                         |
| ----------------------------- | ----------------------------- | --------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `spyperbat.orgui`             | `SPYPERBAT_ORGUID`            |                             | Organization to send output to, if not empty, Spyderbat output is **enabled**                                                       |
| `spyperbat.apikey`            | `SPYPERBAT_APIKEY`            |                             | Spyderbat API key with access to the organization                                                                                   |
| `spyperbat.apiurl`            | `SPYPERBAT_APIURL`            | `https://api.spyderbat.com` | Spyderbat API url                                                                                                                   |
| `spyperbat.source`            | `SPYPERBAT_SOURCE`            | `falcosidekick`             | Spyderbat source ID, max 32 characters                                                                                              |
| `spyperbat.sourcedescription` | `SPYPERBAT_SOURCEDESCRIPTION` |                             | Spyderbat source description and display name if not empty, max 256 characters                                                      |
| `spyperbat.minimumpriority`   | `SPYPERBAT_MINIMUMPRIORITY`   | `""` (= `debug`)            | Minimum priority of event for using this output, order is `emergency,alert,critical,error,warning,notice,informational,debug or ""` |

> [!NOTE]
The Env var values override the settings from yaml file.

## Example of config.yaml

```yaml
spyderbat:
  orguid: "" # Organization to send output to, if not empty, Spyderbat output is enabled
  apikey: "" # Spyderbat API key with access to the organization
  # apiurl: "https://api.spyderbat.com" # Spyderbat API url (default: "https://api.spyderbat.com")
  # source: "falcosidekick" # Spyderbat source ID, max 32 characters (default: "falcosidekick")
  # sourcedescription: "" # Spyderbat source description and display name if not empty, max 256 characters
  # minimumpriority: "debug" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
```

## Additional info

## Screenshots
