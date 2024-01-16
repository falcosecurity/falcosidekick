## What

Via [./docker-compose.yaml](./docker-compose.yaml), runs a stack of:

* `falco`
* `falcosidekick`
* `events-generator` to generate arbitrary falco events
* [Tempo](https://grafana.com/oss/tempo/) as OTLP traces backend
* [Grafana](https://grafana.com/oss/grafana/) for visualization

## Requirements

A local Linux kernel capable of running `falco`--modern-bpf`, see
<https://falco.org/blog/falco-modern-bpf/>.

## Run it

To bring up the stack, and peek at how Grafana shows it:

1. Bring up the stack

  ```
  docker-compose up
  ```

2. Navigate to <http://localhost:3000/> to start browsing the local Grafana UI

3. Navigate to [/explore](http://localhost:3000/explore/), choose `Tempo` datasource, and query `{}`, or just click [here](http://localhost:3000/explore?orgId=1&left=%7B%22datasource%22:%22tempo%22,%22queries%22:%5B%7B%22refId%22:%22A%22,%22datasource%22:%7B%22type%22:%22tempo%22,%22uid%22:%22tempo%22%7D,%22queryType%22:%22traceql%22,%22limit%22:20,%22query%22:%22%7B%7D%22%7D%5D) for such already crafted query.

4. Click on any of the shown traces on the left panel.

5. Bring down the stack

  ```
  docker-compose down
  ```

## Files

* ./docker-compose.yaml: minimal docker-compose configuration
* ./etc/falco/falco.yaml: minimal falco configuration
* ./etc/falco/rules/: from upstream https://github.com/falcosecurity/rules.git
* ./etc/grafana/provisioning/datasources/datasources.yaml: provisioning Tempo backend as Grafana datasource
* ./etc/tempo/config.yaml: minimal tempo configuration
