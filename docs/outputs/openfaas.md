# OpenFaaS

- **Category**: FaaS / Serverlesss
- **Website**: https://www.openfaas.com/

## Table of content

- [OpenFaaS](#openfaas)
  - [Table of content](#table-of-content)
  - [Configuration](#configuration)
  - [Example of config.yaml](#example-of-configyaml)
  - [Additional info](#additional-info)
  - [Screenshots](#screenshots)

## Configuration

| Setting                      | Env var                      | Default value    | Description                                                                                                                         |
| ---------------------------- | ---------------------------- | ---------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `openfaas.functionname`      | `OPENFAAS_FUNCTIONNAME`      |                  | Name of OpenFaaS function, if not empty, OpenFaaS is **enabled**                                                                    |
| `openfaas.functionnamespace` | `OPENFAAS_FUNCTIONNAMESPACE` | `openfaas-fn`    | Namespace of OpenFaaS function                                                                                                      |
| `openfaas.gatewayservice`    | `OPENFAAS_GATEWAYSERVICE`    | `gateway`        | Service of OpenFaaS Gateway                                                                                                         |
| `openfaas.gatewayport`       | `OPENFAAS_GATEWAYPORT`       | `8080`           | Port of service of OpenFaaS Gateway                                                                                                 |
| `openfaas.gatewaynamespace`  | `OPENFAAS_GATEWAYNAMESPACE`  | `openfaas`       | Namespace of OpenFaaS Gateway                                                                                                       |
| `openfaas.kubeconfig`        | `OPENFAAS_KUBECONFIG`        | `~/.kube/config` | Kubeconfig file to use (only if falcosidekick is running outside the cluster)                                                       |
| `openfaas.checkcert`         | `OPENFAAS_CHECKCERT`         | `true`           | Check if ssl certificate of the output is valid                                                                                     |
| `openfaas.minimumpriority`   | `OPENFAAS_MINIMUMPRIORITY`   | `""` (= `debug`) | Minimum priority of event for using this output, order is `emergency,alert,critical,error,warning,notice,informational,debug or ""` |

> [!NOTE]
The Env var values override the settings from yaml file.

## Example of config.yaml

```yaml
openfaas:
  functionname: "" # Name of OpenFaaS function, if not empty, OpenFaaS is enabled
  functionnamespace: "openfaas-fn" # Namespace of OpenFaaS function, "openfaas-fn" (default)
  gatewayservice: "gateway" # Service of OpenFaaS Gateway, "gateway" (default)
  gatewayport: 8080 # Port of service of OpenFaaS Gateway
  gatewaynamespace: "openfaas" # Namespace of OpenFaaS Gateway, "openfaas" (default)
  kubeconfig: "~/.kube/config" # Kubeconfig file to use (only if falcosidekick is running outside the cluster)
  # minimumpriority: "debug" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
  # checkcert: true # check if ssl certificate of the output is valid (default: true)
```

## Additional info

## Screenshots
