# Kubeless

- **Category**: FaaS / Serverless
- **Website**: https://kubeless.io/

## Table of content

- [Kubeless](#kubeless)
  - [Table of content](#table-of-content)
  - [Configuration](#configuration)
  - [Example of config.yaml](#example-of-configyaml)
  - [Additional info](#additional-info)
  - [Screenshots](#screenshots)

## Configuration

| Setting                    | Env var                    | Default value    | Description                                                                                                                         |
| -------------------------- | -------------------------- | ---------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `kubeless.function`        | `KUBELESS_FUNCTION`        |                  | Name of Kubeless function, if not empty, Kubeless is **enabled**                                                                    |
| `kubeless.namespace`       | `KUBELESS_NAMESPACE`       |                  | Namespace of Kubeless function (mandatory)                                                                                          |
| `kubeless.port`            | `KUBELESS_PORT`            | `8080`           | Port of service of Kubeless function                                                                                                |
| `kubeless.port`            | `KUBELESS_PORT`            | `~/.kube/config` | Port of service of Kubeless function                                                                                                |
| `kubeless.kubeconfig`      | `KUBELESS_KUBECONFIG`      | `true`           | Kubeconfig file to use (only if falcosidekick is running outside the cluster)                                                       |
| `kubeless.minimumpriority` | `KUBELESS_MINIMUMPRIORITY` | `""` (= `debug`) | Minimum priority of event for using this output, order is `emergency,alert,critical,error,warning,notice,informational,debug or ""` |

> [!NOTE]
The Env var values override the settings from yaml file.

## Example of config.yaml

```yaml
kubeless:
  function: "" # Name of Kubeless function, if not empty, Kubeless is enabled
  namespace: "" # Namespace of Kubeless function (mandatory)
  port: 8080 # Port of service of Kubeless function
  kubeconfig: "~/.kube/config" # Kubeconfig file to use (only if falcosidekick is running outside the cluster)
  # minimumpriority: "debug" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
  # checkcert: true # check if ssl certificate of the output is valid (default: true)
```

## Additional info

> [!WARNING]
`Kubeless` is no more maintained, consider to use a different output.

## Screenshots
