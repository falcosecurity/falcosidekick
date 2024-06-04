# Falcosidekick

[![Falco Ecosystem Repository](https://github.com/falcosecurity/evolution/blob/main/repos/badges/falco-ecosystem-blue.svg)](https://github.com/falcosecurity/evolution/blob/main/REPOSITORIES.md#ecosystem-scope) [![Stable](https://img.shields.io/badge/status-stable-brightgreen?style=for-the-badge)](https://github.com/falcosecurity/evolution/blob/main/REPOSITORIES.md#stable)

![falcosidekick](https://github.com/falcosecurity/falcosidekick/raw/master/imgs/falcosidekick_color.png)

![release](https://flat.badgen.net/github/release/falcosecurity/falcosidekick/latest?color=green)
![last commit](https://flat.badgen.net/github/last-commit/falcosecurity/falcosidekick)
![licence](https://flat.badgen.net/badge/license/MIT/blue)
![docker pulls](https://flat.badgen.net/docker/pulls/falcosecurity/falcosidekick?icon=docker)

## Description

A simple daemon for connecting [`Falco`](https://github.com/falcosecurity/falco) to your ecosystem. It takes a `Falco` events and
forward them to different outputs in a fan-out way.

It works as a single endpoint for as many as you want `Falco` instances :

![falco_with_falcosidekick](https://github.com/falcosecurity/falcosidekick/raw/master/imgs/falco_with_falcosidekick.png)

## Table of contents

- [Falcosidekick](#falcosidekick)
  - [Description](#description)
  - [Table of contents](#table-of-contents)
  - [Outputs](#outputs)
    - [Chat](#chat)
    - [Metrics / Observability](#metrics--observability)
    - [Alerting](#alerting)
    - [Logs](#logs)
    - [Object Storage](#object-storage)
    - [FaaS / Serverless](#faas--serverless)
    - [Message queue / Streaming](#message-queue--streaming)
    - [Email](#email)
    - [Database](#database)
    - [Web](#web)
    - [SIEM](#siem)
    - [Workflow](#workflow)
    - [Traces](#traces)
    - [Other](#other)
  - [Installation](#installation)
    - [Localhost](#localhost)
      - [With docker](#with-docker)
      - [With systemd](#with-systemd)
    - [In Kubernetes](#in-kubernetes)
      - [With Helm](#with-helm)
    - [Connect Falco](#connect-falco)
      - [with falco.yaml](#with-falcoyaml)
      - [with Helm](#with-helm-1)
    - [Configuration](#configuration)
      - [YAML File](#yaml-file)
  - [Usage](#usage)
  - [Endpoints](#endpoints)
  - [Logs](#logs-1)
  - [Mutual TLS](#mutual-tls)
  - [Metrics](#metrics)
    - [Golang ExpVar](#golang-expvar)
    - [Prometheus](#prometheus)
    - [StatsD / DogStatsD](#statsd--dogstatsd)
  - [Try](#try)
  - [Development](#development)
    - [Build](#build)
    - [Quicktest](#quicktest)
    - [Test \& Coverage](#test--coverage)
  - [Author](#author)

## Outputs

`Falcosidekick` manages a large variety of outputs with different purposes.

> [!NOTE]
Follow the links to get the configuration of each output.

### Chat

- [**Slack**](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/slack.md)
- [**Rocketchat**](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/rocketchat.md)
- [**Mattermost**](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/mattermost.md)
- [**Teams**](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/teams.md)
- [**Discord**](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/discord.md)
- [**Google Chat**](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/googlechat.md)
- [**Zoho Cliq**](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/cliq.md)
- [**Telegram**](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/telegram.md)

### Metrics / Observability

- [**Datadog**](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/datadog.md)
- [**Influxdb**](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/influxdb.md)
- [**StatsD**](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/statsd.md) (for monitoring of `falcosidekick`)
- [**DogStatsD**](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/dogstatsd.md) (for monitoring of `falcosidekick`)
- [**Prometheus**](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/prometheus.md) (for both events and monitoring of `falcosidekick`)
- [**Wavefront**](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/wavefront.md)
- [**Spyderbat**](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/spyderbat.md)
- [**TimescaleDB**](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/timescaledb.md)
- [**Dynatrace**](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/dynatrace.md)

### Alerting

- [**AlertManager**](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/alertmanager.md)
- [**Opsgenie**](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/opsgenie.md)
- [**PagerDuty**](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/pagerduty.md)
- [**Grafana OnCall**](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/grafana_oncall.md)

### Logs

- [**Elasticsearch**](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/elasticsearch.md)
- [**Loki**](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/loki.md)
- [**AWS CloudWatchLogs**](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/aws_cloudwatch_logs.md)
- [**Grafana**](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/grafana.md)
- [**Syslog**](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/syslog.md)
- [**Zincsearch**](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs//zincsearch.md)
- [**OpenObserve**](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/openobserve.md)
- [**SumoLogic**](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/sumologic.md)
- [**Quickwit**](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/quickwit.md)

### Object Storage

- [**AWS S3**](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/aws_s3.md)
- [**GCP Storage**](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/gcp_storage.md)
- [**Yandex S3 Storage**](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/yandex_s3.md)

### FaaS / Serverless

- [**AWS Lambda**](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/aws_lambda.md)
- [**GCP Cloud Run**](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/gcp_cloud_run.md)
- [**GCP Cloud Functions**](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/gcp_cloud_functions.md)
- [**Fission**](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/fission.md)
- [**KNative (CloudEvents)**](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/cloudevents.md)
- [**Kubeless**](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/kubeless.md)
- [**OpenFaaS**](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/openfaas.md)
- [**Tekton**](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/tekton.md)

### Message queue / Streaming

- [**NATS**](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/nats.md)
- [**STAN (NATS Streaming)**](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/stan.md)
- [**AWS SQS**](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/aws_sqs.md)
- [**AWS SNS**](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/aws_sns.md)
- [**AWS Kinesis**](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/aws_kinesis.md)
- [**GCP PubSub**](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/gcp_pub_sub.md)
- [**Apache Kafka**](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/kafka.md)
- [**Kafka Rest Proxy**](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/kafkarest.md)
- [**RabbitMQ**](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/rabbitmq.md)
- [**Azure Event Hubs**](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/azure_event_hub.md)
- [**Yandex Data Streams**](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/yandex_datastreams.md)
- [**MQTT**](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/mqtt.md)
- [**Gotify**](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/gotify.md)

### Email

- [**SMTP**](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/smtp.md)

### Database

- [**Redis**](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/redis.md)

### Web

- [**Webhook**](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/webhook.md)
- [**Node-RED**](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/nodered.md)
- [**WebUI**](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/falcosidekick-ui.md)

### SIEM

- [**AWS Security Lake**](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/aws_security_lake.md)

### Workflow

- [**n8n**](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/n8n.md)

### Traces

- [**OTEL Traces**](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/otlp_traces.md)


### Other
- [**Policy Report**](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/policy_report.md)

## Installation

Run the daemon as any other daemon in your architecture (systemd, k8s deployment, swarm service, ...).

### Localhost

#### With docker

Use the environment variables to set up the outputs:
```bash
docker run -d -p 2801:2801 -e SLACK_WEBHOOKURL=XXXX -e DATADOG_APIKEY=XXXX falcosecurity/falcosidekick
```

#### With systemd

* Download the latest release:
  ```shell
  VER=$(curl --silent -qI https://github.com/falcosecurity/falcosidekick/releases/latest | awk -F '/' '/^location/ {print  substr($NF, 1, length($NF)-1)}')
  wget -c https://github.com/falcosecurity/falcosidekick/releases/download/${VER}/falcosidekick_${VER}_linux_arm64.tar.gz -O - | tar -xz
  or
  wget -c https://github.com/falcosecurity/falcosidekick/releases/download/${VER}/falcosidekick_${VER}_linux_amd64.tar.gz -O - | tar -xz
  chmod +x falcosidekick
  sudo mv falcosidekick /usr/local/bin/
  ```

* Create the `/etc/falcosidekick/config.yaml` file, see [Configuration](#configuration).

* Create the systemd unit files `/etc/systemd/system/falcosidekick.service`:
  ```shell
  sudo touch /etc/systemd/system/falcosidekick.service
  sudo chmod 664 /etc/systemd/system/falcosidekick.service
  ```
  ```toml
  [Unit]
  Description=Falcosidekick
  After=network.target
  StartLimitIntervalSec=0

  [Service]
  Type=simple
  Restart=always
  RestartSec=1
  ExecStart=/usr/local/bin/falcosidekick -c /etc/falcosidekick/config.yaml

  [Install]
  WantedBy=default.target
  ```

* Reload `systemd` and start `Falcosidekick`:
  ```shell
  sudo systemctl daemon-reload
  sudo systemctl enable falcosidekick
  sudo systemctl start falcosidekick
  ```

* Check if `Falcosidekick` runs:
  ```shell
  curl localhost:2801/healthz
  ```  

### In Kubernetes

#### With Helm

See
[https://github.com/falcosecurity/charts/blob/master/charts/falcosidekick/README.md](https://github.com/falcosecurity/charts/blob/master/charts/falcosidekick/README.md)

```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update

helm install falcosidekick --set config.debug=true falcosecurity/falcosidekick
```

> [!NOTE]
You can also deploy `falcosidekick` as a dependency of the `falco` chart, the settings for the communication between falco and `falcosidekick` are automatically set. Just prefix all `falcosidekick` settings with `falcosidekick.`:
```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update

helm install falco --set falcosidekick.enabled=true falcosecurity/falco
```

### Connect Falco

To connect Falco with Falcosidekick, you need to change it configuration as following:

#### with falco.yaml

If managing _falco.yaml_ manually, set this:

```yaml
json_output: true
json_include_output_property: true
http_output:
  enabled: true
  url: "http://localhost:2801/"
```

#### with Helm

If installing `falco` with `Helm`, set this (adapted to your environment) in
your _values.yaml_ :

```yaml
falcosidekick:
  enabled: true
```

or

```yaml
jsonOutput: true
jsonIncludeOutputProperty: true
httpOutput:
  enabled: true
  url: "http://falcosidekick:2801/"
```

or

```yaml
jsonOutput: true
jsonIncludeOutputProperty: true
programOutput:
  enabled: true
  keepAlive: false
  program: "curl -d @- falcosidekick:2801/"
```

### Configuration

Configuration is made by _file (yaml)_ and _env vars_, both can be used but _env
vars_ override values from _file_.

#### YAML File

See **config_example.yaml** :

```yaml
#listenaddress: "" # ip address to bind falcosidekick to (default: "" meaning all addresses)
#listenport: 2801 # port to listen for daemon (default: 2801)
debug: false # if true all outputs will print in stdout the payload they send (default: false)
customfields: # custom fields are added to falco events, if the value starts with % the relative env var is used
  # Akey: "AValue"
  # Bkey: "BValue"
  # Ckey: "CValue"
templatedfields: # templated fields are added to falco events and metrics, it uses Go template + output_fields values
  # Dkey: '{{ or (index . "k8s.ns.labels.foo") "bar" }}'
# bracketreplacer: "_" # if not empty, replace the brackets in keys of Output Fields
outputFieldFormat: "<timestamp>: <priority> <output> <custom_fields> <templated_fields>" # if not empty, allow to change the format of the output field. (default: "<timestamp>: <priority> <output>")
mutualtlsfilespath: "/etc/certs" # folder which will used to store client.crt, client.key and ca.crt files for mutual tls for outputs, will be deprecated in the future (default: "/etc/certs")
mutualtlsclient: # takes priority over mutualtlsfilespath if not emtpy
  certfile: "/etc/certs/client/client.crt" # client certification file
  keyfile: "/etc/certs/client/client.key" # client key
  cacertfile: "/etc/certs/client/ca.crt" # for server certification
tlsclient:
  cacertfile: "/etc/certs/client/ca.crt" # CA certificate file for server certification on TLS connections, appended to the system CA pool if not empty
tlsserver:
  deploy: false # if true, TLS server will be deployed instead of HTTP
  certfile: "/etc/certs/server/server.crt" # server certification file
  keyfile: "/etc/certs/server/server.key" # server key
  mutualtls: false # if true, mTLS server will be deployed instead of TLS, deploy also has to be true
  cacertfile: "/etc/certs/server/ca.crt" # for client certification if mutualtls is true
  notlsport: 2810 # port to serve http server serving selected endpoints (default: 2810)
  notlspaths: # if not empty, and tlsserver.deploy is true, a separate http server will be deployed for the specified endpoints
    - "/ping"
    # - "/metrics"
    # - "/healthz"
```

> [!NOTE]
For the confiuration of the outputs, see the [docs](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/).

## Usage

Usage :

```bash
usage: falcosidekick [<flags>]

Flags:
      --help                     Show context-sensitive help (also try --help-long and --help-man).
  -c, --config-file=CONFIG-FILE  config file
```

## Endpoints

Different endpoints (handlers) are available :

- `/` : main and default handler, your falco config must be configured to use it
- `/ping` : you will get a `pong` as answer, useful to test if falcosidekick is running and its port is opened (for healthcheck purpose for example). This endpoint is deprecated and it will be removed in `3.0.0`.
- `/healthz`: you will get a HTTP status code `200` response as answer, useful to test if falcosidekick is running and its port is opened (for healthcheck or purpose for example)
- `/test` : (for debug only) send a test event to all enabled outputs.
- `/debug/vars` : get statistics from daemon (in JSON format), it uses classic `expvar` package and some custom values are added
- `/metrics` : prometheus endpoint, for scraping metrics about events and `falcosidekick`

## Logs

All logs are sent to `stdout`.

```bash
2019/05/10 14:32:06 [INFO] : Enabled Outputs : Slack Datadog
```

## Mutual TLS ##

Outputs with `mutualtls` enabled in their configuration require the *client.crt*, *client.key* and *ca.crt* filepaths to be configured in the **mutualtlsclient_certfile**, **mutualtlsclient_keyfile** and  **mutualtlsclient_cacertfile** global parameter.

```bash
docker run -d -p 2801:2801 -e MUTUALTLSCLIENT_CERTFILE=/etc/certs/client/client.crt -e MUTUALTLSCLIENT_KEYFILE=/etc/certs/client/client.key -e MUTUALTLSCLIENT_CACERTFILE=/etc/certs/client/ca.crt -e ALERTMANAGER_HOSTPORT=https://XXXX -e ALERTMANAGER_MUTUALTLS=true -e INFLUXDB_HOSTPORT=https://XXXX -e INFLUXDB_MUTUALTLS=true -e WEBHOOK_ADDRESS=XXXX -v /localpath/myclientcert.crt:/etc/certs/client/client.crt -v /localpath/myclientkey.key:/etc/certs/client/client.key -v /localpath/ca.crt:/etc/certs/client/ca.crt falcosecurity/falcosidekick
```

Alternately the path where the *client.crt*, *client.key* and *ca.crt* files are stored can be configured in **mutualtlsfilespath** global parameter. (**Important**: file names must be preserved)

```bash
docker run -d -p 2801:2801 -e MUTUALTLSFILESPATH=/etc/certs -e ALERTMANAGER_HOSTPORT=https://XXXX -e ALERTMANAGER_MUTUALTLS=true -e INFLUXDB_HOSTPORT=https://XXXX -e INFLUXDB_MUTUALTLS=true -e WEBHOOK_ADDRESS=XXXX -v /localpath/myclientcert.crt:/etc/certs/client.crt -v /localpath/myclientkey.key:/etc/certs/client.key -v /localpath/ca.crt:/etc/certs/ca.crt falcosecurity/falcosidekick
```

In above example, the same client certificate will be used for both Alertmanager & InfluxDB outputs which have mutualtls flag set to true.

## Metrics

### Golang ExpVar

The daemon exposes the common _Golang_ metrics and some custom values in JSON
format. It's useful for monitoring purpose.

![expvar json](https://github.com/falcosecurity/falcosidekick/raw/master/imgs/expvar_json.png)
![expvarmon](https://github.com/falcosecurity/falcosidekick/raw/master/imgs/expvarmon.png)

### Prometheus

The daemon exposes a `prometheus` endpoint on URI `/metrics`.

See the [docs](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/prometheus.md) for more info.

### StatsD / DogStatsD

The daemon is able to push its metrics to a StatsD/DogstatsD server. See
[Configuration](https://github.com/falcosecurity/falcosidekick#configuration)
section for how-to.

See the [statsd docs](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/statsd.md) and [dogstastd docs](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/dogstatsd.md)  for more info.

## Try

Run you daemon and try (from Falco's documentation):

```bash
curl -XPOST "http://localhost:2801/" -d'{"output":"16:31:56.746609046: Error File below a known binary directory opened for writing (user=root command=touch /bin/hack file=/bin/hack)","hostname": "localhost", "priority":"Error","rule":"Write below binary dir","time":"2019-05-17T15:31:56.746609046Z", "output_fields": {"evt.time":1507591916746609046,"fd.name":"/bin/hack","proc.cmdline":"touch /bin/hack","user.name":"root"}}'
```

## Development

### Build

```bash
make falcosidekick
```

### Quicktest

Create a debug event

```bash
curl -X POST -H "Content-Type: application/json" -H "Accept: application/json" localhost:2801/test
```

### Test & Coverage

```bash
make test
```

With Coverage

```bash
make test-coverage
```

## Author

Thomas Labarussias (https://github.com/Issif)
