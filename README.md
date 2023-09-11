# Falcosidekick

[![Falco Ecosystem Repository](https://github.com/falcosecurity/evolution/blob/main/repos/badges/falco-ecosystem-blue.svg)](https://github.com/falcosecurity/evolution/blob/main/REPOSITORIES.md#ecosystem-scope) [![Stable](https://img.shields.io/badge/status-stable-brightgreen?style=for-the-badge)](https://github.com/falcosecurity/evolution/blob/main/REPOSITORIES.md#stable)

![falcosidekick](https://github.com/falcosecurity/falcosidekick/raw/master/imgs/falcosidekick_color.png)

![release](https://flat.badgen.net/github/release/falcosecurity/falcosidekick/latest?color=green)
![last commit](https://flat.badgen.net/github/last-commit/falcosecurity/falcosidekick)
![licence](https://flat.badgen.net/badge/license/MIT/blue)
![docker pulls](https://flat.badgen.net/docker/pulls/falcosecurity/falcosidekick?icon=docker)
[![falcosidekick](https://circleci.com/gh/falcosecurity/falcosidekick.svg?style=shield)](https://circleci.com/gh/falcosecurity/falcosidekick)

## Description

A simple daemon for connecting [`Falco`](https://github.com/falcosecurity/falco) to your ecosystem. It takes a `Falco`'s events and
forward them to different outputs in a fan-out way.

It works as a single endpoint for as many as you want `Falco` instances :

![falco_with_falcosidekick](https://github.com/falcosecurity/falcosidekick/raw/master/imgs/falco_with_falcosidekick.png)

## Outputs

`Falcosidekick` manages a large variety of outputs with different purposes.

### Chat

- [**Slack**](https://slack.com)
- [**Rocketchat**](https://rocket.chat/)
- [**Mattermost**](https://mattermost.com/)
- [**Teams**](https://products.office.com/en-us/microsoft-teams/group-chat-software)
- [**Discord**](https://www.discord.com/)
- [**Google Chat**](https://workspace.google.com/products/chat/)
- [**Zoho Cliq**](https://www.zoho.com/cliq/)
- [**Telegram**](https://telegram.org)

### Metrics / Observability

- [**Datadog**](https://www.datadoghq.com/)
- [**Influxdb**](https://www.influxdata.com/products/influxdb-overview/)
- [**StatsD**](https://github.com/statsd/statsd) (for monitoring of `falcosidekick`)
- [**DogStatsD**](https://docs.datadoghq.com/developers/dogstatsd/?tab=go) (for monitoring of `falcosidekick`)
- [**Prometheus**](https://prometheus.io/) (for both events and monitoring of `falcosidekick`)
- [**Wavefront**](https://www.wavefront.com)
- [**Spyderbat**](https://www.spyderbat.com)
- [**TimescaleDB**](https://www.timescale.com/)
- [**Dynatrace**](https://www.dynatrace.com/)

### Alerting

- [**AlertManager**](https://prometheus.io/docs/alerting/alertmanager/)
- [**Opsgenie**](https://www.opsgenie.com/)
- [**PagerDuty**](https://pagerduty.com/)
- [**Grafana OnCall**](https://grafana.com/products/oncall/)

### Logs

- [**Elasticsearch**](https://www.elastic.co/)
- [**Loki**](https://grafana.com/oss/loki)
- [**AWS CloudWatchLogs**](https://aws.amazon.com/cloudwatch/features/)
- [**Grafana**](https://grafana.com/) (annotations)
- **Syslog**
- [**Zincsearch**](https://docs.zincsearch.com/)
- [**OpenObserve**](https://openobserve.ai)

### Object Storage

- [**AWS S3**](https://aws.amazon.com/s3/features/)
- [**GCP Storage**](https://cloud.google.com/storage)
- [**Yandex S3 Storage**](https://cloud.yandex.com/en-ru/services/storage)

### FaaS / Serverless

- [**AWS Lambda**](https://aws.amazon.com/lambda/features/)
- [**GCP Cloud Run**](https://cloud.google.com/run)
- [**GCP Cloud Functions**](https://cloud.google.com/functions)
- [**Fission**](https://fission.io)
- [**KNative (CloudEvents)**](https://knative.dev)
- [**Kubeless**](https://kubeless.io/)
- [**OpenFaaS**](https://www.openfaas.com)
- [**Tekton**](https://tekton.dev)

### Message queue / Streaming

- [**NATS**](https://nats.io/)
- [**STAN (NATS Streaming)**](https://docs.nats.io/nats-streaming-concepts/intro)
- [**AWS SQS**](https://aws.amazon.com/sqs/features/)
- [**AWS SNS**](https://aws.amazon.com/sns/features/)
- [**AWS Kinesis**](https://aws.amazon.com/kinesis/)
- [**GCP PubSub**](https://cloud.google.com/pubsub)
- [**Apache Kafka**](https://kafka.apache.org/)
- [**Kafka Rest Proxy**](https://docs.confluent.io/platform/current/kafka-rest/index.html)
- [**RabbitMQ**](https://www.rabbitmq.com/)
- [**Azure Event Hubs**](https://azure.microsoft.com/en-in/services/event-hubs/)
- [**Yandex Data Streams**](https://cloud.yandex.com/en/docs/data-streams/)
- [**MQTT**](https://mqtt.org/)
- [**Gotify**](https://gotify.net/)

### Email

- **SMTP**

### Web

- **Webhook**
- [**Node-RED**](https://nodered.org/)
- [**WebUI**](https://github.com/falcosecurity/falcosidekick-ui) (a Web UI for displaying latest events in real time)

### SIEM

- [**AWS Security Lake**](https://aws.amazon.com/security-lake/)

### Workflow

- [**n8n**](https://n8n.io/)

### Other
- [**Policy Report**](https://github.com/kubernetes-sigs/wg-policy-prototypes/tree/master/policy-report/falco-adapter)

## Usage

Run the daemon as any other daemon in your architecture (systemd, k8s daemonset,
swarm service, ...)

### With docker

```bash
docker run -d -p 2801:2801 -e SLACK_WEBHOOKURL=XXXX -e DATADOG_APIKEY=XXXX falcosecurity/falcosidekick
```

### With Helm

See
[https://github.com/falcosecurity/charts/blob/master/falcosidekick/README.md](https://github.com/falcosecurity/charts/blob/master/falcosidekick/README.md)

```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update

helm install falcosidekick --set config.debug=true falcosecurity/falcosidekick
```

### Falco's config

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
  # notlspaths: # if not empty, a separate http server will be deployed for the specified endpoints
    # - "/metrics"
    # - "/healthz"


slack:
  webhookurl: "" # Slack WebhookURL (ex: https://hooks.slack.com/services/XXXX/YYYY/ZZZZ), if not empty, Slack output is enabled
  #channel: "" # Slack channel (optionnal)
  #footer: "" # Slack footer
  #icon: "" # Slack icon (avatar)
  #username: "" # Slack username (default: Falcosidekick)
  outputformat: "all" # all (default), text, fields
  minimumpriority: "debug" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
  messageformat: 'Alert : rule *{{ .Rule }}* triggered by user *{{ index
    .OutputFields "user.name" }}*' # a Go template to format Slack Text above Attachment, displayed in addition to the output from `SLACK_OUTPUTFORMAT`, see [Slack Message Formatting](#slack-message-formatting) in the README for details. If empty, no Text is displayed before Attachment.

rocketchat:
  webhookurl: "" # Rocketchat WebhookURL (ex: http://XXXX/hooks/YYYY), if not empty, Rocketchat output is enabled
  #icon: "" # Rocketchat icon (avatar)
  #username: "" # Rocketchat username (default: Falcosidekick)
  outputformat: "all" # all (default), text, fields
  minimumpriority: "debug" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
  # messageformat: "Alert : rule *{{ .Rule }}* triggered by user *{{ index .OutputFields \"user.name\" }}*" # a Go template to format Rocketchat Text above Attachment, displayed in addition to the output from `ROCKETCHAT_OUTPUTFORMAT`, see [Slack Message Formatting](#slack-message-formatting) in the README for details. If empty, no Text is displayed before Attachment.
  # mutualtls: false # if true, checkcert flag will be ignored (server cert will always be checked)
  # checkcert: true # check if ssl certificate of the output is valid (default: true)

mattermost:
  webhookurl: "" # Mattermost WebhookURL (ex: http://XXXX/hooks/YYYY), if not empty, Mattermost output is enabled
  #footer: "" # Mattermost footer
  #icon: "" # Mattermost icon (avatar)
  #username: "" # Mattermost username (default: Falcosidekick)
  outputformat: "all" # all (default), text, fields
  minimumpriority: "debug" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
  # messageformat: "Alert : rule **{{ .Rule }}** triggered by user **{{ index .OutputFields \"user.name\" }}**" # a Go template to format Mattermost Text above Attachment, displayed in addition to the output from `MATTERMOST_OUTPUTFORMAT`, see [Slack Message Formatting](#slack-message-formatting) in the README for details. If empty, no Text is displayed before Attachment.
  # mutualtls: false # if true, checkcert flag will be ignored (server cert will always be checked)
  # checkcert: true # check if ssl certificate of the output is valid (default: true)

teams:
  webhookurl: "" # Teams WebhookURL (ex: https://hooks.slack.com/services/XXXX/YYYY/ZZZZ), if not empty, Teams output is enabled
  #activityimage: "" # Image for message section
  outputformat: "text" # all (default), text, facts
  minimumpriority: "debug" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)

datadog:
  # apikey: "" # Datadog API Key, if not empty, Datadog output is enabled
  # host: "" # Datadog host. Override if you are on the Datadog EU site. Defaults to american site with "https://api.datadoghq.com"
  # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)

alertmanager:
  # hostport: "" # http://{domain or ip}:{port}, if not empty, Alertmanager output is enabled
  # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
  # mutualtls: false # if true, checkcert flag will be ignored (server cert will always be checked)
  # checkcert: true # check if ssl certificate of the output is valid (default: true)
  # endpoint: "" # alertmanager endpoint for posting alerts: "/api/v1/alerts" or "/api/v2/alerts" (default: "/api/v1/alerts")
  # expiresafter: "" if set to a non-zero value, alert expires after that time in seconds (default: 0)
  # extralabels: "" # comma separated list of labels composed of a ':' separated name and value that is added to the Alerts. Example: my_label_1:my_value_1, my_label_1:my_value_2
  # extraannotations: "" # comma separated list of annotations composed of a ':' separated name and value that is added to the Alerts. Example: my_annotation_1:my_value_1, my_annotation_1:my_value_2
  # customseveritymap: "" # comma separated list of tuple composed of a ':' separated Falco priority and Alertmanager severity that is used to override the severity label associated to the priority level of falco event. Example: debug:value_1,critical:value2.  Default mapping (priority:severity): emergency:critical,alert:critical,critical:critical,error:warning,warning:warning,notice:information,informational:information,debug:information
  # dropeventdefaultpriority: "" # default priority of dropped events, values are emergency|alert|critical|error|warning|notice|informational|debug (default: "critical")
  # dropeventthresholds: # comma separated list of priority re-evaluation thresholds of dropped events composed of a ':' separated integer threshold and string priority. Example: `10000:critical, 100:warning, 1:informational` (default: `"10000:critical, 1000:critical, 100:critical, 10:warning, 1:warning"`)

elasticsearch:
  # hostport: "" # http://{domain or ip}:{port}, if not empty, Elasticsearch output is enabled
  # index: "falco" # index (default: falco)
  # type: "_doc"
  # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
  # suffix: "daily" # date suffix for index rotation : daily (default), monthly, annually, none
  # mutualtls: false # if true, checkcert flag will be ignored (server cert will always be checked)
  # checkcert: true # check if ssl certificate of the output is valid (default: true)
  # username: "" # use this username to authenticate to Elasticsearch if the username is not empty (default: "")
  # password: "" # use this password to authenticate to Elasticsearch if the password is not empty (default: "")
  # customHeaders: # Custom headers to add in POST, useful for Authentication
  #   key: value

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

loki:
  # hostport: "" # http://{domain or ip}:{port}, if not empty, Loki output is enabled
  # user: "" # user for Grafana Logs
  # apikey: "" # API Key for Grafana Logs
  # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
  # checkcert: true # check if ssl certificate of the output is valid (default: true)
  # tenant: "" # Add the tenant header if needed. Enabled if not empty
  # endpoint: "/api/prom/push" # The endpoint URL path, default is "/api/prom/push" more info : https://grafana.com/docs/loki/latest/api/#post-apiprompush
  # extralabels: "" # comma separated list of fields to use as labels additionally to rule, source, priority, tags and custom_fields
  # customHeaders: # Custom headers to add in POST, useful for Authentication
  #   key: value

stan:
  # hostport: "" # nats://{domain or ip}:{port}, if not empty, STAN output is enabled
  # clusterid: "" # Cluster name, if not empty, STAN output is enabled
  # clientid: "" # Client ID, if not empty, STAN output is enabled
  # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
  # mutualtls: false # if true, checkcert flag will be ignored (server cert will always be checked)
  # checkcert: true # check if ssl certificate of the output is valid (default: true)

nats:
  # hostport: "" # nats://{domain or ip}:{port}, if not empty, NATS output is enabled
  # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
  # mutualtls: false # if true, checkcert flag will be ignored (server cert will always be checked)
  # checkcert: true # check if ssl certificate of the output is valid (default: true)

aws:
  # accesskeyid: "" # aws access key (optional if you use EC2 Instance Profile)
  # secretaccesskey: "" # aws secret access key (optional if you use EC2 Instance Profile)
  # region : "" # aws region (by default, the metadata are used to get it)
  # rolearn: "" # aws role to assume (optional if you use EC2 Instance Profile)
  # externalid: "" # external id for the role to assume (optional if you use EC2 Instance Profile)
  # checkidentity: true # check the identity credentials, set to false for locale developments (default: true)
  lambda:
    # functionname : "" # Lambda function name, if not empty, AWS Lambda output is enabled
    # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
  sqs:
    # url : "" # SQS Queue URL, if not empty, AWS SQS output is enabled
    # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
  sns:
    # topicarn : "" # SNS TopicArn, if not empty, AWS SNS output is enabled
    rawjson: false # Send Raw JSON or parse it (default: false)
    # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
  cloudwatchlogs:
    # loggroup : "" #  AWS CloudWatch Logs Group name, if not empty, CloudWatch Logs output is enabled
    # logstream : "" # AWS CloudWatch Logs Stream name, if empty, Falcosidekick will try to create a log stream
    # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
  s3:
    # bucket: "falcosidekick" # AWS S3, bucket name
    # prefix : "" # name of prefix, keys will have format: s3://<bucket>/<prefix>/YYYY-MM-DD/YYYY-MM-DDTHH:mm:ss.s+01:00.json
    # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
  securitylake.:
    # bucket: "" # Bucket for AWS SecurityLake data, if not empty, AWS SecurityLake output is enabled
    # region: "" # Bucket Region
    # prefix: "" # Prefix for keys
    # accountid: "" # Account ID
    interval: 5 # Time in minutes between two puts to S3 (must be between 5 and 60min) (default: 5min)
    batchsize: 1000 # Max number of events by parquet file (default: 1000)
    # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
  kinesis:
    # streamname: "" # AWS Kinesis Stream Name, if not empty, Kinesis output is enabled
    # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)

smtp:
  # hostport: "" # host:port address of SMTP server, if not empty, SMTP output is enabled
  # tls: true # use TLS connection (true/false), default is "true"
  # authmechanism: "plain" # SASL Mechanisms : plain, oauthbearer, external, anonymous or none (disable SASL). Default: plain
  # user: "" # user for Plain Mechanism
  # password: "" # password for Plain Mechanism
  # token: "" # OAuthBearer token for OAuthBearer Mechanism
  # identity: "" # identity string for Plain and External Mechanisms
  # trace: "" trace string for Anonymous Mechanism
  # from: "" # Sender address (mandatory if SMTP output is enabled)
  # to: "" # comma-separated list of Recipident addresses, can't be empty (mandatory if SMTP output is enabled)
  # outputformat: "" # html (default), text
  # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)

prometheus:
  # extralabels: "" # comma separated list of fields to use as labels additionally to rule, source, priority, tags and custom_fields

statsd:
  forwarder: "" # The address for the StatsD forwarder, in the form "host:port", if not empty StatsD is enabled
  namespace: "falcosidekick." # A prefix for all metrics (default: "falcosidekick.")

dogstatsd:
  forwarder: "" # The address for the DogStatsD forwarder, in the form "host:port", if not empty DogStatsD is enabled
  namespace: "falcosidekick." # A prefix for all metrics (default: "falcosidekick.")
  # tag :
  #   key: "value"

opsgenie:
  # apikey: "2c771471-e2af-4dc6-bd35-e7f6ff479b64" # Opsgenie API Key, if not empty, Opsgenie output is enabled
  region: "eu" # (us|eu) region of your domain
  # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)

webhook:
  # address: "" # Webhook address, if not empty, Webhook output is enabled
  # method: "POST" # Webhook http method: POST or PUT (default: POST)
  # customHeaders: # Custom headers to add in the request, useful for Authentication
  #   key: value
  # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
  # mutualtls: false # if true, checkcert flag will be ignored (server cert will always be checked)
  # checkcert: true # check if ssl certificate of the output is valid (default: true)

nodered:
  # address: "" # Webhook address, if not empty, Webhook output is enabled
  # user: "" # User if Basic Auth is enabled for 'http in' node in Node-RED
  # password: "" # Password if Basic Auth is enabled for 'http in' node in Node-RED
  # customHeaders: # Custom headers to add in POST, useful for Authentication
  #   key: value
  # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
  # checkcert: true # check if ssl certificate of the output is valid (default: true)

azure:
  eventHub:
    name: "" # Name of the Hub, if not empty, EventHub is enabled
    namespace: "" # Name of the space the Hub is in
    # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)

discord:
  webhookurl: "" # discord WebhookURL (ex: https://discord.com/api/webhooks/xxxxxxxxxx...), if not empty, Discord output is enabled
  # icon: "" # Discord icon (avatar)
  # minimumpriority: "debug" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)

gcp:
  credentials: "" # The base64-encoded JSON key file for the GCP service account
  pubsub:
    projectid: "" # The GCP Project ID containing the Pub/Sub Topic
    topic: "" # The name of the Pub/Sub topic
    # minimumpriority: "debug" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
    # customAttributes: # Custom attributes to add to the Pub/Sub messages
    #   key: value
  storage:
    # prefix : "" # name of prefix, keys will have format: gs://<bucket>/<prefix>/YYYY-MM-DD/YYYY-MM-DDTHH:mm:ss.s+01:00.json
    bucket: "" # The name of the bucket
    # minimumpriority: "debug" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
  cloudfunctions:
    name: "" # The name of the Cloud Function
    # minimumpriority: "debug" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
  cloudrun:
    endpoint: "" # The URL of the Cloud Function
    jwt: "" # Appropriate JWT to invoke the Cloud Function
    # minimumpriority: "debug" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)

googlechat:
  webhookurl: "" # Google Chat WebhookURL (ex: https://chat.googleapis.com/v1/spaces/XXXXXX/YYYYYY), if not empty, Google Chat output is enabled
  # outputformat: "" # all (default), text
  # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
  messageformat: 'Alert : rule *{{ .Rule }}* triggered by user *{{ index
    .OutputFields "user.name" }}*' # a Go template to format Google Chat Text above Attachment, displayed in addition to the output from `GOOGLECHAT_OUTPUTFORMAT`, see [Slack Message Formatting](#slack-message-formatting) in the README for details. If empty, no Text is displayed before Attachment.

cliq:
  webhookurl: "" # WebhookURL (ex: https://cliq.zoho.eu/api/v2/channelsbyname/XXXX/message?zapikey=YYYY), if not empty, Cliq output is enabled
  # icon: "" # Cliq icon (avatar)
  # useemoji: true # Prefix message text with an emoji
  # outputformat: "all" # all (default), text, fields
  # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
  messageformat: 'Alert : rule *{{ .Rule }}* triggered by user *{{ index
    .OutputFields "user.name" }}*' # a Go template to format Cliq Text above Table, displayed in addition to the output from `CLIQ_OUTPUTFORMAT`, see [Slack Message Formatting](#slack-message-formatting) in the README for details. If empty, no Text is displayed before Table.

kafka:
  hostport: "" # comma separated list of Apache Kafka bootstrap nodes for establishing the initial connection to the cluster (ex: localhost:9092,localhost:9093). Defaults to port 9092 if no port is specified after the domain, if not empty, Kafka output is enabled
  topic: "" # Name of the topic, if not empty, Kafka output is enabled
  # minimumpriority: "debug" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
  sasl: "" # SASL authentication mechanism, if empty, no authentication (PLAIN|SCRAM_SHA256|SCRAM_SHA512)
  tls: false # Use TLS for the connections (default: false)
  username: "" # use this username to authenticate to Kafka via SASL (default: "")
  password: "" # use this password to authenticate to Kafka via SASL (default: "")
  # async: false # produce messages without blocking (default: false)
  # requiredacks: NONE # number of acknowledges from partition replicas required before receiving (default: "NONE")
  # compression: "" # enable message compression using this algorithm, no compression (GZIP|SNAPPY|LZ4|ZSTD|NONE) (default: "NONE")
  # balancer: "" # partition balancing strategy when producing, (default: "round_robin")
  # clientid: "" # specify a client.id when communicating with the broker for tracing
  # topiccreation: false # auto create the topic if it doesn't exist (default: false)

kafkarest:
  address: "" # The full URL to the topic (example "http://kafkarest:8082/topics/test")
  #version: 2 # Kafka Rest Proxy API version 2|1 (default: 2)
  # minimumpriority: "debug" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
  # mutualtls: false # if true, checkcert flag will be ignored (server cert will always be checked)
  # checkcert: true # check if ssl certificate of the output is valid (default: true)

pagerduty:
  routingKey: "" # Pagerduty Routing Key, if not empty, Pagerduty output is enabled
  region: "us" # Pagerduty Region, can be 'us' or 'eu' (default: us)
  minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)

kubeless:
  function: "" # Name of Kubeless function, if not empty, Kubeless is enabled
  namespace: "" # Namespace of Kubeless function (mandatory)
  port: 8080 # Port of service of Kubeless function
  kubeconfig: "~/.kube/config" # Kubeconfig file to use (only if falcoside is running outside the cluster)
  # minimumpriority: "debug" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
  # checkcert: true # check if ssl certificate of the output is valid (default: true)

openfaas:
  functionname: "" # Name of OpenFaaS function, if not empty, OpenFaaS is enabled
  functionnamespace: "openfaas-fn" # Namespace of OpenFaaS function, "openfaas-fn" (default)
  gatewayservice: "gateway" # Service of OpenFaaS Gateway, "gateway" (default)
  gatewayport: 8080 # Port of service of OpenFaaS Gateway
  gatewaynamespace: "openfaas" # Namespace of OpenFaaS Gateway, "openfaas" (default)
  kubeconfig: "~/.kube/config" # Kubeconfig file to use (only if falcosidekick is running outside the cluster)
  # minimumpriority: "debug" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
  # checkcert: true # check if ssl certificate of the output is valid (default: true)

rabbitmq:
  url: "" # Rabbitmq URL, if not empty, Rabbitmq output is enabled
  queue: "" # Rabbitmq Queue name
  # minimumpriority: "debug" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)

wavefront:
  endpointtype: "direct" # Wavefront endpoint type, must be 'direct' or 'proxy'. If not empty, with endpointhost, Wavefront output is enabled
  endpointhost: "" # Wavefront endpoint address (only the host). If not empty, with endpointhost, Wavefront output is enabled
  endpointmetricport: 2878 # Wavefront endpoint port when type is 'proxy'
  endpointtoken: "" # Wavefront token. Must be used only when endpointtype is 'direct'
  metricname: "falco.alert" # Metric to be created in Wavefront. Defaults to falco.alert
  batchsize: 10000 # max batch of data sent per flush interval. defaults to 10,000. Used only in direct mode
  flushintervalseconds: 1 # Time in seconds between flushing metrics to Wavefront. Defaults to 1s
  # minimumpriority: "debug" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)

fission:
  function: "" # Name of Fission function, if not empty, Fission is enabled
  routernamespace: "fission" # Namespace of Fission Router, "fission" (default)
  routerservice: "router" # Service of Fission Router, "router" (default)
  routerport: 80 # Port of service of Fission Router
  # minimumpriority: "debug" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
  # checkcert: true # check if ssl certificate of the output is valid (default: true)
  # mutualtls: false # if true, checkcert flag will be ignored (server cert will always be checked)

grafana:
  hostport: "" # http://{domain or ip}:{port}, if not empty, Grafana output is enabled
  apikey: "" # API Key to authenticate to Grafana, if not empty, Grafana output is enabled
  # dashboardid:  # annotations are scoped to a specific dashboard. Optionnal.
  # panelid: "" # annotations are scoped to a specific panel. Optionnal.
  # allfieldsastags: false # if true, all custom fields are added as tags (default: false)
  # mutualtls: false # if true, checkcert flag will be ignored (server cert will always be checked)
  # checkcert: true # check if ssl certificate of the output is valid (default: true)
  # minimumpriority: "debug" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
  # customHeaders: # Custom headers to add in POST, useful for Authentication
  #   key: value

grafanaoncall:
  webhookurl: "" # if not empty, Grafana OnCall output is enabled
  # mutualtls: false # if true, checkcert flag will be ignored (server cert will always be checked)
  # checkcert: true # check if ssl certificate of the output is valid (default: true)
  # customHeaders: # Custom headers to add in POST, useful for Authentication
  #   key: value
  # minimumpriority: "debug" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)

policyreport:
  enabled: false  # if true; policyreport output is enabled
  kubeconfig: "~/.kube/config"  # Kubeconfig file to use (only if falcosidekick is running outside the cluster)
  minimumpriority: "debug" # events with a priority above this are mapped to fail in PolicyReport Summary and lower that those are mapped to warn (default="")
  maxevents: 1000 # the max number of events that can be in a policyreport (default: 1000)
  prunebypriority: false # if true; the events with lowest severity are pruned first, in FIFO order (default: false)

webui:
  url: "" # WebUI URL, if not empty, WebUI output is enabled

yandex:
  # accesskeyid: "" # yandex access key
  # secretaccesskey: "" # yandex secret access key
  # region: "" # yandex storage region (default: ru-central-1)
  s3:
    # endpoint: "" # yandex storage endpoint (default: https://storage.yandexcloud.net)
    # bucket: "falcosidekick" # Yandex storage, bucket name
    # prefix: "" # name of prefix, keys will have format: s3://<bucket>/<prefix>/YYYY-MM-DD/YYYY-MM-DDTHH:mm:ss.s+01:00.json
    # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug
  datastreams:
    # endpoint: "" # Yandex Data Streams endpoint (default: https://yds.serverless.yandexcloud.net)
    # streamname: "" # stream name in format /${region}/${folder_id}/${ydb_id}/${stream_name}
    # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug

syslog:
  # host: "" # Syslog host, if not empty, Syslog output is enabled
  # port: "" # Syslog endpoint port number
  # protocol: "" # Syslog transport protocol. It can be either "tcp" or "udp" (default: tcp)
  # format: "" # Syslog payload format. It can be either "json" or "cef" (default: json)
  # minimumpriority: "debug" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)

mqtt:
  broker: "" # Broker address, can start with tcp:// or ssl://, if not empty, MQTT output is enabled
  # topic: "falco/events" # Topic for messages (default: falco/events)
  # qos: 0 # QOS for messages (default: 0)
  # retained: false # If true, messages are retained (default: false)
  # user: "" # User if the authentication is enabled in the broker
  # password: "" # Password if the authentication is enabled in the broker
  # checkcert: true # check if ssl certificate of the output is valid (default: true)
  # minimumpriority: "debug" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)

zincsearch:
  # hostport: "" # http://{domain or ip}:{port}, if not empty, ZincSearch output is enabled
  # index: "falco" # index (default: falco)
  # username: "" # use this username to authenticate to ZincSearch (default: "")
  # password: "" # use this password to authenticate to ZincSearch (default: "")
  # checkcert: true # check if ssl certificate of the output is valid (default: true)
  # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)

gotify:
  # hostport: "" # http://{domain or ip}:{port}, if not empty, Gotify output is enabled
  # token: "" # API Token
  # format: "markdown" # Format of the messages (plaintext, markdown, json) (default: markdown)
  # checkcert: true # check if ssl certificate of the output is valid (default: true)
  # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)

tekton:
  # eventListener: "" # EventListener address, if not empty, Tekton output is enabled
  # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
  # mutualtls: false # if true, checkcert flag will be ignored (server cert will always be checked)
  # checkcert: true # check if ssl certificate of the output is valid (default: true)

spyderbat:
  # orguid: "" # Organization to send output to, if not empty, Spyderbat output is enabled
  # apikey: "" # Spyderbat API key with access to the organization
  # apiurl: "https://api.spyderbat.com" # Spyderbat API url (default: "https://api.spyderbat.com")
  # source: "falcosidekick" # Spyderbat source ID, max 32 characters (default: "falcosidekick")
  # sourcedescription: "" # Spyderbat source description and display name if not empty, max 256 characters
  # minimumpriority: "debug" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)

timescaledb:
  # host: "" # TimescaleDB host, if not empty, TImescaleDB output is enabled
  # port: "5432" # TimescaleDB port (default: 5432)
  # user: "postgres" # Username to authenticate with TimescaleDB (default: postgres)
  # password: "postgres" # Password to authenticate with TimescaleDB (default: postgres)
  # database: "" # TimescaleDB database used
  # hypertablename: "falco_events" # Hypertable to store data events (default: falco_events) See TimescaleDB setup for more info
  # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
redis:
  # address: "" # Redis address, if not empty, Redis output is enabled
  # password: "" # Password to authenticate with Redis (default: "")
  # database: "" # Redis database number (default: 0)
  # storagetype: "" # Redis storage type: hashmap or list (default: list)
  # key: "" # Redis storage key name for hashmap, list(default: "falco")
  # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)

telegram:
  # token: "" # telegram bot authentication token
  # chatid: "" # telegram Identifier of the shared chat
  # checkcert: true # check if ssl certificate of the output is valid (default: true)
  # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)

n8n:
  # address: "" # N8N address, if not empty, N8N output is enabled
  # user: "" # Username to authenticate with N8N in basic auth
  # password: "" # Password to authenticate with N8N in basic auth
  # headerauthname: "" # Header Auth Key to authenticate with N8N
  # headerauthvalue: "" # Header Auth Value to authenticate with N8N
  # checkcert: true # check if ssl certificate of the output is valid (default: true)
  # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)

openobserve:
  # hostport: "" # http://{domain or ip}:{port}, if not empty, OpenObserve output is enabled
  # organizationName: "default" # Organization name (default: default)
  # streamName: "falco" # Stream name (default: falco)
  # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
  # mutualtls: false # if true, checkcert flag will be ignored (server cert will always be checked)
  # checkcert: true # check if ssl certificate of the output is valid (default: true)
  # username: "a" # use this username to authenticate to OpenObserve if the username is not empty (default: "")
  # password: "" # use this password to authenticate to OpenObserve if the password is not empty (default: "")
  # customHeaders: # Custom headers to add in POST, useful for Authentication
  #   key: value

dynatrace:
  apitoken: "" # Dynatrace API token with the "logs.ingest" scope, more info : https://dt-url.net/8543sda, if not empty, Dynatrace output is enabled
  apiurl: "" # Dynatrace API url, use https://ENVIRONMENTID.live.dynatrace.com/api for Dynatrace SaaS and https://YOURDOMAIN/e/ENVIRONMENTID/api for Dynatrace Managed, more info : https://dt-url.net/ej43qge
  # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
  # checkcert: true # check if ssl certificate of the output is valid (default: true)
```

Usage :

```bash
usage: falcosidekick [<flags>]

Flags:
      --help                     Show context-sensitive help (also try --help-long and --help-man).
  -c, --config-file=CONFIG-FILE  config file
```

#### Env vars

Configuration of the daemon can be made also by _env vars_, these values
override these from _yaml file_.

The _env vars_ "match" field names in \*yaml file with this structure (**take
care of lower/uppercases**) : `yaml: a.b --> envvar: A_B` :

- **LISTENADDRESS** : ip address to bind falcosidekick to (default: "" meaning all addresses)
- **LISTENPORT** : port to listen for daemon (default: `2801`)
- **DEBUG** : if _true_ all outputs will print in stdout the payload they send
  (default: false)
- **CUSTOMFIELDS** : a list of comma separated custom fields to add to falco, if the value starts with % the relative env var is used
  events, syntax is "key:value,key:value"
- **TEMPLATEDFIELDS** : templated fields are added to falco events and metrics, it uses Go template + output_fields values
- **BRACKETREPLACER** : if not empty, the brackets in keys of Output Fields are replaced
- **MUTUALTLSFILESPATH**: path which will be used to stored certs and key for mutual TLS authentication, will be deprecated in the future (default: "/etc/certs")
- **MUTUALTLSCLIENT_CERTFILE**: client certification file for mutual TLS client certification, takes priority over MUTUALTLSFILESPATH if not empty
- **MUTUALTLSCLIENT_KEYFILE**: client key file for mutual TLS client certification, takes priority over MUTUALTLSFILESPATH if not empty
- **MUTUALTLSCLIENT_CACERTFILE**: CA certification file for server certification for mutual TLS authentication, takes priority over MUTUALTLSFILESPATH if not empty
- **TLSCLIENT_CACERTFILE**: CA certificate file for server certification on TLS connections, appended to the system CA pool if not empty
- **TLSSERVER_DEPLOY**: if _true_ TLS server will be deployed instead of HTTP
- **TLSSERVER_CERTFILE**: server certification file for TLS Server (default: "/etc/certs/server/server.crt")
- **TLSSERVER_KEYFILE**: server key file for TLS Server (default: "/etc/certs/server/server.key")
- **TLSSERVER_MUTUALTLS**: if _true_ mutual TLS server will be deployed instead of TLS, deploy also has to be true
- **TLSSERVER_CACERTFILE**: CA certification file for client certification if TLSSERVER_MUTUALTLS is _true_ (default: "/etc/certs/server/ca.crt")
- **TLSSERVER_NOTLSPORT**: port to serve http server serving selected endpoints (default: 2810)
- **TLSSERVER_NOTLSPATHS**: a comma separated list of endpoints, if not empty, a separate http server will be deployed for the specified endpoints (e.g.: "/metrics,/healtz")
- **SLACK_WEBHOOKURL** : Slack Webhook URL (ex: https://hooks.slack.com/services/XXXX/YYYY/ZZZZ)
- **SLACK_CHANNEL** : Slack Channel (optionnal)
- **SLACK_FOOTER** : Slack footer
- **SLACK_ICON** : Slack icon (avatar)
- **SLACK_USERNAME** : Slack username (default: `Falcosidekick`)
- **SLACK_OUTPUTFORMAT** : `all` (default), `text` (only text is displayed in
  Slack), `fields` (only fields are displayed in Slack)
- **SLACK_MINIMUMPRIORITY** : minimum priority of event for using use this
  output, order is
  `emergency|alert|critical|error|warning|notice|informational|debug or "" (default)`
- **SLACK_MESSAGEFORMAT** : a Go template to format Slack Text above Attachment,
  displayed in addition to the output from `SLACK_OUTPUTFORMAT`, see
  [Slack Message Formatting](#slack-message-formatting) in the README for
  details. If empty, no Text is displayed before Attachment.
- **ROCKETCHAT_WEBHOOKURL** : Rocketchat Webhook URL (ex:
  https://XXXX/hooks/YYYY), if not `empty`, Rocketchat output is _enabled_
- **ROCKETCHAT_ICON** : Rocketchat icon (avatar)
- **ROCKETCHAT_USERNAME** : Rocketchat username (default: `Falcosidekick`)
- **ROCKETCHAT_OUTPUTFORMAT** : `all` (default), `text` (only text is displayed
  in Rocketchat), `fields` (only fields are displayed in Rocketchat)
- **ROCKETCHAT_MINIMUMPRIORITY** : minimum priority of event for using use this
  output, order is
  `emergency|alert|critical|error|warning|notice|informational|debug or "" (default)`
- **ROCKETCHAT_MESSAGEFORMAT** : a Go template to format Rocketchat Text above
  Attachment, displayed in addition to the output from
  `ROCKETCHAT_OUTPUTFORMAT`, see
  [Slack Message Formatting](#slack-message-formatting) in the README for
  details. If empty, no Text is displayed before Attachment.
- **ROCKETCHAT_MUTUALTLS** : enable mutual tls authentication for this output (default:
  `false`)
- **ROCKETCHAT_CHECKCERT** : check if ssl certificate of the output is valid (default:
  `true`)
- **MATTERMOST_WEBHOOKURL** : Mattermost Webhook URL (ex:
  https://XXXX/hooks/YYYY), if not `empty`, Mattermost output is _enabled_
- **MATTERMOST_FOOTER** : Mattermost footer
- **MATTERMOST_ICON** : Mattermost icon (avatar)
- **MATTERMOST_USERNAME** : Mattermost username (default: `Falcosidekick`)
- **MATTERMOST_OUTPUTFORMAT** : `all` (default), `text` (only text is displayed
  in Mattermost), `fields` (only fields are displayed in Mattermost)
- **MATTERMOST_MINIMUMPRIORITY** : minimum priority of event for using use this
  output, order is
  `emergency|alert|critical|error|warning|notice|informational|debug or "" (default)`
- **MATTERMOST_MESSAGEFORMAT** : a Go template to format Mattermost Text above
  Attachment, displayed in addition to the output from
  `MATTERMOST_OUTPUTFORMAT`, see
  [Mattermost Message Formatting](#slack-message-formatting) in the README for
  details. If empty, no Text is displayed before Attachment.
- **MATTERMOST_MUTUALTLS** : enable mutual tls authentication for this output (default:
  `false`)
- **MATTERMOST_CHECKCERT** : check if ssl certificate of the output is valid (default:
  `true`)
- **TEAMS_WEBHOOKURL** : Teams Webhook URL (ex:
  https://outlook.office.com/webhook/XXXXXX/IncomingWebhook/YYYYYY"), if not
  `empty`, Teams output is _enabled_
- **TEAMS_ACTIVITYIMAGE** : Teams section image
- **TEAMS_OUTPUTFORMAT** : `all` (default), `text` (only text is displayed in
  Teams), `facts` (only facts are displayed in Teams)
- **TEAMS_MINIMUMPRIORITY** : minimum priority of event for using use this
  output, order is
  `emergency|alert|critical|error|warning|notice|informational|debug or "" (default)`
- **DATADOG_APIKEY** : Datadog API Key, if not `empty`, Datadog output is
  _enabled_
- **DATADOG_HOST** : Datadog host. Override if you are on the Datadog EU site.
  Defaults to american site with "https://api.datadoghq.com"
- **DATADOG_MINIMUMPRIORITY** : minimum priority of event for using this output,
  order is
  `emergency|alert|critical|error|warning|notice|informational|debug or "" (default)`
- **DISCORD_WEBHOOKURL** : Discord WebhookURL (ex:
  https://discord.com/api/webhooks/xxxxxxxxxx...), if not empty, Discord output
  is _enabled_
- **DISCORD_ICON** : Discord icon (avatar)
- **DISCORD_MINIMUMPRIORITY** : minimum priority of event for using use this
  output, order is
  `emergency|alert|critical|error|warning|notice|informational|debug or "" (default)`
- **ALERTMANAGER_HOSTPORT** : AlertManager http://host:port, if not `empty`,
  AlertManager is _enabled_
- **ALERTMANAGER_MINIMUMPRIORITY** : minimum priority of event for using this
  output, order is
  `emergency|alert|critical|error|warning|notice|informational|debug or "" (default)`
- **ALERTMANAGER_MUTUALTLS** : enable mutual tls authentication for this output (default:
  `false`)
- **ALERTMANAGER_CHECKCERT** : check if ssl certificate of the output is valid (default:
  `true`)
- **ALERTMANAGER_ENDPOINT** : alertmanager endpoint on which falcosidekick posts alerts, choice is:
  `"/api/v1/alerts" or "/api/v2/alerts" , default is "/api/v1/alerts"`
- **ALERTMANAGER_EXPIRESAFTER** : if set to a non-zero value, alert expires after that time in seconds (default: 0)
- **ALERTMANAGER_EXTRALABELS** : comma separated list of labels composed of a ':' separated name and value that is 
  added to the Alerts. Example: `my_label_1:my_value_1, my_label_1:my_value_2` (default: `""`)
- **ALERTMANAGER_EXTRAANNOTATIONS** : comma separated list of annotations composed of a ':' separated name and
  value that is added to the Alerts. Example: `my_annotation_1:my_value_1, my_annotation_1:my_value_2` (default: `""`)
- **ALERTMANAGER_CUSTOMSEVERITYMAP** : comma separated list of tuple composed of a ':' separated Falco priority and
  Alertmanager severity that is used to override the severity label associated to the priority level of falco event.
  Example: `debug:value_1,critical:value2`. Default mapping (priority:severity): `emergency:critical,alert:critical,critical:critical,error:warning,warning:warning,notice:information,informational:information,debug:information` (default: `""`)
- **ALERTMANAGER_DROPEVENTDEFAULTPRIORITY** : default priority of dropped events, values are emergency|alert|critical|error|warning|notice|informational|debug (default: `"critical"`)
- **ALERTMANAGER_DROPEVENTTHRESHOLDS** : comma separated list of priority re-evaluation thresholds of dropped events composed of a ':' separated integer threshold and
  string priority. Example: `10000:critical, 100:warning, 1:informational` (default: `"10000:critical, 1000:critical, 100:critical, 10:warning, 1:warning"`)
- **ELASTICSEARCH_HOSTPORT** : Elasticsearch http://host:port, if not `empty`,
  Elasticsearch is _enabled_
- **ELASTICSEARCH_INDEX** : Elasticsearch index (default: falco)
- **ELASTICSEARCH_TYPE** : Elasticsearch document type (default: _doc)
- **ELASTICSEARCH_MINIMUMPRIORITY** : minimum priority of event for using this
  output, order is
  `emergency|alert|critical|error|warning|notice|informational|debug or "" (default)`
- **ELASTICSEARCH_SUFFIX** : date suffix for index rotation : `daily` (default),
  `monthly`, `annually`, `none`
- **ELASTICSEARCH_MUTUALTLS** : enable mutual tls authentication for this output (default:
  `false`)
- **ELASTICSEARCH_CHECKCERT** : check if ssl certificate of the output is valid (default:
  `true`)
- **ELASTICSEARCH_USERNAME** : use this username to authenticate to Elasticsearch if the
  username is not empty (default: "")
- **ELASTICSEARCH_PASSWORD** : use this password to authenticate to Elasticsearch if the
  password is not empty (default: "")
- **ELASTICSEARCH_CUSTOMHEADERS** : a list of comma separated custom headers to add,
  syntax is "key:value,key:value"
- **INFLUXDB_HOSTPORT** : Influxdb http://host:port, if not `empty`, Influxdb is
  _enabled_
- **INFLUXDB_DATABASE** : Influxdb database (default: falco)
- **INFLUXDB_ORGANIZATION** : Influxdb database (api v1 only) (default: falco)
- **INFLUXDB_BUCKET** : Influxdb organization
- **INFLUXDB_USER** : bucket (default: falco)
- **INFLUXDB_PASSWORD** : user to use if auth is enabled in Influxdb
- **INFLUXDB_TOKEN** : API token to use if auth in enabled in Influxdb (disables user and password)
- **INFLUXDB_PRECISION** : write precision
- **INFLUXDB_MINIMUMPRIORITY** : minimum priority of event for using this
  output, order is
  `emergency|alert|critical|error|warning|notice|informational|debug or "" (default)`
- **INFLUXDB_MUTUALTLS** : enable mutual tls authentication for this output (default:
  `false`)
- **INFLUXDB_CHECKCERT** : check if ssl certificate of the output is valid (default:
  `true`)
- **LOKI_HOSTPORT** : Loki http://host:port, if not `empty`, Loki is _enabled_
- **LOKI_USER** : User for Grafana Logs
- **LOKI_APIKEY** : API Key for Grafana Logs
- **LOKI_MINIMUMPRIORITY** : minimum priority of event for using this output,
  order is
  `emergency|alert|critical|error|warning|notice|informational|debug or "" (default)`
- **LOKI_CHECKCERT** : check if ssl certificate of the output is valid (default:
  `true`)
- **LOKI_TENANT** : Loki tenant, if not `empty`, Loki tenant is _enabled_
- **LOKI_ENDPOINT** : Loki endpoint URL path, default is "/api/prom/push" more info : https://grafana.com/docs/loki/latest/api/#post-apiprompush
- **NATS_HOSTPORT** : NATS "nats://host:port", if not `empty`, NATS is _enabled_
- **LOKI_EXTRALABELS** : comma separated list of fields to use as labels additionally to rule, source, priority, tags and custom_fields
- **LOKI_CUSTOMHEADERS** : a list of comma separated custom headers to add,
  syntax is "key:value,key:value"
- **NATS_MINIMUMPRIORITY** : minimum priority of event for using this output,
  order is
  `emergency|alert|critical|error|warning|notice|informational|debug or "" (default)`
- **NATS_MUTUALTLS** : enable mutual tls authentication for this output (default:
  `false`)
- **NATS_CHECKCERT** : check if ssl certificate of the output is valid (default:
  `true`)
- **STAN_HOSTPORT** : NATS "nats://host:port", if not `empty`, STAN is _enabled_
- **STAN_CLUSTERID** : Cluster name, if not `empty`, STAN is _enabled_
- **STAN_CLIENTID** : Client ID to use, if not `empty`, STAN is _enabled_
- **STAN_MINIMUMPRIORITY** : minimum priority of event for using this output,
  order is
- **STAN_MUTUALTLS** : enable mutual tls authentication for this output (default:
  `false`)
- **STAN_CHECKCERT** : check if ssl certificate of the output is valid (default:
  `true`)
  `emergency|alert|critical|error|warning|notice|informational|debug or "" (default)`
- **AWS_ACCESSKEYID** : AWS Access Key Id (optional if you use EC2 Instance
  Profile)
- **AWS_SECRETACCESSKEY** : AWS Secret Access Key (optional if you use EC2
  Instance Profile)
- **AWS_REGION** : AWS Region (by default, the metadata are used to get it)
- **AWS_ROLEARN** : AWS role to assume (optional if you use EC2 Instance Profile)
- **AWS_EXTERNALID** : External id for the role to assume (optional if you use EC2 Instance Profile)
- **AWS_CHECKIDENTITY** : Check the identity credentials, set to false for locale developments (default: true)
- **AWS_LAMBDA_FUNCTIONNAME** : AWS Lambda Function Name, if not empty, AWS
  Lambda output is _enabled_
- **AWS_LAMBDA_MINIMUMPRIORITY** : minimum priority of event for using this
  output, order is
  `emergency|alert|critical|error|warning|notice|informational|debug or "" (default)`
- **AWS_SQS_URL** : AWS SQS Queue URL, if not empty, AWS SQS output is _enabled_
- **AWS_SQS_MINIMUMPRIORITY** : minimum priority of event for using this output,
  order is
  `emergency|alert|critical|error|warning|notice|informational|debug or "" (default)`
- **AWS_SNS_TOPICARN** : AWS SNS TopicARN, if not empty, AWS SNS output is
  _enabled_
- **AWS_SNS_RAWJSON** : Send Raw JSON or parse it (default: false)
- **AWS_SNS_MINIMUMPRIORITY** : minimum priority of event for using this output,
  order is
  `emergency|alert|critical|error|warning|notice|informational|debug or "" (default)`
- **AWS_CLOUDWATCHLOGS_LOGGROUP** : AWS CloudWatch Logs Group name, if not
  empty, CloudWatch Logs output is enabled
- **AWS_CLOUDWATCHLOGS_LOGSTREAM** : AWS CloudWatch Logs Stream name, if empty,
  FalcoSideKick will try to create a log stream
- **AWS_CLOUDWATCHLOGS_MINIMUMPRIORITY** : minimum priority of event for using
  this output, order is
  `emergency|alert|critical|error|warning|notice|informational|debug or "" (default)`
- **AWS_S3_BUCKET** : AWS S3 Bucket, if not empty, AWS S3 output is
    _enabled_
- **AWS_S3_PREFIX** : Prefix name of the object, keys will have format: s3://<bucket>/<prefix>/YYYY-MM-DD/YYYY-MM-DDTHH:mm:ss.s+01:00.json
- **AWS_S3_MINIMUMPRIORITY** : minimum priority of event for using this output,
- **AWS_SECURITYLAKE_BUCKET** : Bucket for AWS SecurityLake data, if not empty, AWS SecurityLake. output is _enabled_
- **AWS_SECURITYLAKE_REGION** : Bucket Region (mandatory)
- **AWS_SECURITYLAKE_PREFIX** : Prefix for keys (mandatory)
- **AWS_SECURITYLAKE_ACCOUNTID** : Account ID (mandatory)
- **AWS_SECURITYLAKE_INTERVAL** : Time in minutes between two puts to S3 (must be between 5 and 60min) (default: 5min)
- **AWS_SECURITYLAKE_BATCHSIZE** : Max number of events by parquet file (default: 1000)
- **AWS_SECURITYLAKE_PREFIX** : Prefix name of the object, keys will have format: s3://<bucket>/<prefix>/YYYY-MM-DD/YYYY-MM-DDTHH:mm:ss.s+01:00.json
- **AWS_SECURITYLAKE_MINIMUMPRIORITY** : minimum priority of event for using this output,
  order is
- **AWS_KINESIS_STREAMNAME** : AWS Kinesis Stream Name, if not empty, Kinesis output is enabled
- **AWS_KINESIS_MINIMUMPRIORITY** : minimum priority of event for using
  this output, order is
  `emergency|alert|critical|error|warning|notice|informational|debug or "" (default)`
- **SMTP_HOSTPORT** : "host:port" address of SMTP server, if not empty, SMTP
  output is _enabled_
- **SMTP_TLS** : use TLS connection (true/false), default is "true"
- **SMTP_FROM** : Sender address (mandatory if SMTP output is enabled)
- **SMTP_TO** : comma-separated list of Recipident addresses, can't be empty
  (mandatory if SMTP output is enabled)
- **SMTP_OUTPUTFORMAT** : "" # html (default), text
- **SMTP_MINIMUMPRIORITY** : minimum priority of event for using this output,
  order is
  `emergency|alert|critical|error|warning|notice|informational|debug or "" (default)`
- **SMTP_AUTHMECHANISM** : SASL Mechanisms `plain|oauthbearer|external|anonymous or none (disable SASL)` Default to `plain`
- **SMTP_USER** :  user for Plain Mechanism
- **SMTP_PASSWORD** : password for Plain Mechanism
- **SMTP_TOKEN** : # OAuthBearer token for OAuthBearer Mechanism
- **SMTP_IDENTITY** : identity string for Plain and External Mechanisms
- **SMTP_TRACE** : trace string for Anonymous Mechanism
- **OPSGENIE_APIKEY** : Opsgenie API Key, if not empty, Opsgenie output is _enabled_
- **OPSGENIE_REGION** : (us|eu) region of your domain (default is 'us')
- **OPSGENIE_MINIMUMPRIORITY** : minimum priority of event for using this
  output, order is
  `emergency|alert|critical|error|warning|notice|informational|debug or "" (default)`
- **PROMETHEUS_EXTRALABELS**: comma separated list of fields to use as labels additionally to rule, source, priority, tags and custom_fields
- **STATSD_FORWARDER**: The address for the StatsD forwarder, in the form
  http://host:port, if not empty StatsD is _enabled_
- **STATSD_NAMESPACE**: A prefix for all metrics (default: "falcosidekick.")
- **DOGSTATSD_FORWARDER**: The address for the DogStatsD forwarder, in the form
  http://host:port, if not empty DogStatsD is _enabled_
- **DOGSTATSD_NAMESPACE**: A prefix for all metrics (default: falcosidekick."")
- **DOGSTATSD_TAGS**: A comma-separated list of tags to add to all metrics
- **WEBHOOK_ADDRESS** : Webhook address, if not empty, Webhook output is
  _enabled_
- **WEBHOOK_METHOD** : HTTP method: POST or PUT (default: POST)
- **WEBHOOK_CUSTOMHEADERS** : a list of comma separated custom headers to add,
  syntax is "key:value,key:value"
- **WEBHOOK_MINIMUMPRIORITY** : minimum priority of event for using this output,
  order is
  `emergency|alert|critical|error|warning|notice|informational|debug or "" (default)`
- **WEBHOOK_MUTUALTLS** : enable mutual tls authentication for this output (default:
  `false`)
- **WEBHOOK_CHECKCERT** : check if ssl certificate of the output is valid (default:
  `true`)
- **NODERED_ADDRESS** : Node-RED address, if not empty, Node-RED output is
  _enabled_
- **NODERED_USER** : User if Basic Auth is enabled for 'http in' node
  in Node-RED
- **NODERED_PASSWORD** : Password if Basic Auth is enabled for 'http in' node
  in Node-RED
- **NODERED_CUSTOMHEADERS** : a list of comma separated custom headers to add,
  syntax is "key:value,key:value"
- **NODERED_MINIMUMPRIORITY** : minimum priority of event for using this output,
  order is
  `emergency|alert|critical|error|warning|notice|informational|debug or "" (default)`
- **NODERED_CHECKCERT** : check if ssl certificate of the output is valid (default:
  `true`)
- **CLOUDEVENTS_ADDRESS** : CloudEvents consumer address, if not empty,
  CloudEvents output is _enabled_
- **CLOUDEVENTS_EXTENSIONS** : a list of comma separated extensions to add,
  syntax is "key:value,key:value"
- **CLOUDEVENTS_MINIMUMPRIORITY** : minimum priority of event for using this
  output, order is
  `emergency|alert|critical|error|warning|notice|informational|debug or "" (default)`
- **AZURE_EVENTHUB_NAME**: Name of the Hub, if not empty, EventHub is _enabled_
- **AZURE_EVENTHUB_NAMESPACE**: Name of the space the Hub is in
- **AZURE_EVENTHUB_MINIMUMPRIORITY**: minimum priority of event for using this
  output, order is
  `emergency|alert|critical|error|warning|notice|informational|debug or "" (default)`
- **GCP_CREDENTIALS**: The base64-encoded JSON key file for the GCP service
  account
- **GCP_PUBSUB_PROJECTID**: The GCP Project ID containing the Pub/Sub Topic
- **GCP_PUBSUB_TOPIC**: The name of the Pub/Sub topic
- **GCP_PUBSUB_MINIMUMPRIORITY**: minimum priority of event for using this
  output, order is
  `emergency|alert|critical|error|warning|notice|informational|debug or "" (default)`
- **GCP_PUBSUB_CUSTOMATTRIBUTES**: a list of comma separated custom headers to add,
  syntax is "key:value,key:value"
- **GCP_STORAGE_BUCKET**: The name of the bucket
- **GCP_STORAGE_PREFIX**: name of prefix, keys will have format: gs://<bucket>/<prefix>/YYYY-MM-DD/YYYY-MM-DDTHH:mm:ss.s+01:00.json
- **GCP_STORAGE_MINIMUMPRIORITY**: minimum priority of event for using this
  output, order is
  `emergency|alert|critical|error|warning|notice|informational|debug or "" (default)`
- **GCP_CLOUDFUNCTIONS_NAME**: The name of the Cloud Function
- **GCP_CLOUDFUNCTIONS_MINIMUMPRIORITY**: minimum priority of event for using this
  output, order is
  `emergency|alert|critical|error|warning|notice|informational|debug or "" (default)`
- **GCP_CLOUDRUN_ENDPOINT**: The URL of the Cloud Function
- **GCP_CLOUDRUN_JWT**: Appropriate token for invoking Cloud Function
- **GCP_CLOUDRUN_MINIMUMPRIORITY**: minimum priority of event for using this
  output, order is
  `emergency|alert|critical|error|warning|notice|informational|debug or "" (default)`
- **GOOGLECHAT_WEBHOOKURL** : Google Chat URL (ex:
  https://chat.googleapis.com/v1/spaces/XXXXXX/YYYYYY), if not `empty`, Google
  Chat output is _enabled_
- **GOOGLECHAT_OUTPUTFORMAT** : `all` (default), `text` (only text is displayed
  in Google Chat)
- **GOOGLECHAT_MINIMUMPRIORITY** : minimum priority of event for using this
  output, order is
  `emergency|alert|critical|error|warning|notice|informational|debug or "" (default)`
- **GOOGLECHAT_MESSAGEFORMAT** : a Go template to format Google Chat Text above
  Attachment, displayed in addition to the output from
  `GOOGLECHAT_OUTPUTFORMAT`, see
  [Slack Message Formatting](#slack-message-formatting) in the README for
  details. If empty, no Text is displayed before sections.
- **CLIQ_WEBHOOKURL**: Zoho Cliq Channel URL (ex:
  https://cliq.zoho.eu/api/v2/channelsbyname/XXXX/message?zapikey=YYYY), if not `empty`, Cliq
  Chat output is _enabled_
- **CLIQ_ICON**: Cliq icon (avatar)
- **CLIQ_USEEMOJI**: Prefix message text with an emoji
- **CLIQ_OUTPUTFORMAT**: `all` (default), `text` (only text is displayed in
  Cliq), `fields` (only fields are displayed in Cliq)
- **CLIQ_MINIMUMPRIORITY**: minimum priority of event for using this
  output, order is
  `emergency|alert|critical|error|warning|notice|informational|debug or "" (default)`
- **CLIQ_MESSAGEFORMAT**: a Go template to format Google Chat Text above
  Attachment, displayed in addition to the output from
  `CLIQ_OUTPUTFORMAT`, see
  [Slack Message Formatting](#slack-message-formatting) in the README for
  details. If empty, no Text is displayed before sections.
- **KAFKA_HOSTPORT**: comma separated list of Apache Kafka bootstrap nodes for establishing the initial connection to the cluster (ex: localhost:9092,localhost:9093). Defaults to port 9092 if no port is specified after the domain, if not empty, Kafka output is _enabled_
- **KAFKA_TOPIC**: The name of the Kafka topic
- **KAFKA_SASL**: "" SASL authentication mechanism, if empty, no authentication (PLAIN|SCRAM_SHA256|SCRAM_SHA512)
- **KAFKA_TLS**: "" Use TLS for the connections (default: false)
- **KAFKA_USERNAME**: use this username to authenticate to Kafka via SASL (default: "")
- **KAFKA_PASSWORD**: use this password to authenticate to Kafka via SASL (default: "")
- **KAFKA_ASYNC**: produce messages without blocking (default: false)
- **KAFKA_REQUIREDACKS**: number of acknowledges from partition replicas required before receiving (default: "NONE")
- **KAFKA_COMPRESSION**: enable message compression using this algorithm, no compression (GZIP|SNAPPY|LZ4|ZSTD|NONE) (default: "NONE")
- **KAFKA_BALANCER**: partition balancing strategy when producing, (default: "round_robin")
- **KAFKA_CLIENTID**: specify a client.id when communicating with the broker for tracing
- **KAFKA_TOPICCREATION**: auto create the topic if it doesn't exist (default: false)
- **KAFKA_MINIMUMPRIORITY**: minimum priority of event for using this output,
  order is
  `emergency|alert|critical|error|warning|notice|informational|debug or "" (default)`
- **KAFKAREST_ADDRESS**: The full URL to the topic (example "http://kafkarest:8082/topics/test")
- **KAFKAREST_VERSION**: Kafka Rest Proxy API version 2|1 (default: 2)
- **KAFKAREST_MINIMUMPRIORITY** : minimum priority of event for using this output, order is
  `emergency|alert|critical|error|warning|notice|informational|debug or "" (default)`
- **KAFKAREST_MUTUALTLS** : enable mutual tls authentication for this output (default: `false`)
- **KAFKAREST_CHECKCERT** : check if ssl certificate of the output is valid (default: `true`)
- **PAGERDUTY_ROUTINGKEY**: Pagerduty Region, can be 'us' or 'eu' (default: us)
- **PAGERDUTY_REGION**: Pagerduty Region, if not empty, Pagerduty output is
  _enabled_
- **PAGERDUTY_MINIMUMPRIORITY**: minimum priority of event for using this
  output, order is
  `emergency|alert|critical|error|warning|notice|informational|debug or "" (default)`
- **KUBELESS_FUNCTION**: Name of Kubeless function, if not empty, Kubeless is
  _enabled_
- **KUBELESS_NAMESPACE**: Namespace of Kubeless function (mandatory)
- **KUBELESS_PORT**: Port of service of Kubeless function (default is `8080`)
- **KUBELESS_KUBECONFIG**: Kubeconfig file to use (only if falcoside is running
  outside the cluster)
- **KUBELESS_MINIMUMPRIORITY**: "debug" # minimum priority of event for using
  this output, order is
  `emergency|alert|critical|error|warning|notice|informational|debug or "" (default)`
- **KUBELESS_CHECKCERT** : check if ssl certificate of the output is valid (default:
  `true`)
- **OPENFAAS_GATEWAYNAMESPACE** : Namespace of OpenFaaS Gateway, "openfaas" (default)
- **OPENFAAS_GATEWAYSERVICE** : Service of OpenFaaS Gateway, "gateway" (default)
- **OPENFAAS_FUNCTIONNAME** : Name of OpenFaaS function, if not empty, OpenFaaS is enabled
- **OPENFAAS_FUNCTIONNAMESPACE** : # Namespace of OpenFaaS function, "openfaas-fn" (default)
- **OPENFAAS_GATEWAYPORT** : Port of service of OpenFaaS Gateway
- **OPENFAAS_KUBECONFIG** : Kubeconfig file to use (only if falcoside is running
  outside the cluster)
- **OPENFAAS_MINIMUMPRIORITY** : "debug" # minimum priority of event for using
  this output, order is
  `emergency|alert|critical|error|warning|notice|informational|debug or "" (default)`
- **OPENFAAS_CHECKCERT** : check if ssl certificate of the output is valid (default:
  `true`)
- **WEBUI_URL** : WebUI URL, if not empty, WebUI output is
  _enabled_
- **RABBITMQ_URL**: Rabbitmq URL, if not empty, Rabbitmq output is enabled
- **RABBITMQ_QUEUE**: # Rabbitmq Queue name
- **RABBITMQ_MINIMUMPRIORITY**: "debug" # minimum priority of event for using
  this output, order is
- **WAVEFRONT_ENDPOINTTYPE**: Wavefront endpoint type: direct or proxy
- **WAVEFRONT_ENDPOINTHOST**: Wavefront endpoint host
- **WAVEFRONT_ENDPOINTTOKEN**: Wavefront API token to be used when the type is 'direct'
- **WAVEFRONT_ENDPOINTMETRICPORT**: Wavefront endpoint port when type is 'proxy'
- **WAVEFRONT_FLUSHINTERVALSECONDS**: Time in seconds between flushing metrics to Wavefront. Defaults to 1s
- **WAVEFRONT_BATCHSIZE**: Max batch of data sent per flush interval. Used only in direct mode. Defaults to 10000.
- **WAVEFRONT_METRICNAME**: "falco.alert" # Metric name to be created/used in Wavefront
- **WAVEFRONT_MINIMUMPRIORITY**: "debug" # minimum priority of event for using
  this output, order is `emergency|alert|critical|error|warning|notice|informational|debug or "" (default)`
- **FISSION_FUNCTION**: Name of Fission function, if not empty, Fission is enabled
- **FISSION_ROUTERNAMESPACE**: Namespace of Fission Router, "fission" (default)
- **FISSION_ROUTERSERVICE**: Service of Fission Router, "router" (default)
- **FISSION_ROUTERPORT**: Port of service of Fission Router
- **FISSION_MINIMUMPRIORITY**: "debug" # minimum priority of event for using
  this output, order is `emergency|alert|critical|error|warning|notice|informational|debug or "" (default)`
- **FISSION_MUTUALTLS**: if true, checkcert flag will be ignored (server cert will always be checked)
- **FISSION_CHECKCERT**: check if ssl certificate of the output is valid (default: `true`)
- **GRAFANA_HOSTPORT**: http://{domain or ip}:{port}, if not empty, Grafana output is enabled
- **GRAFANA_APIKEY**: API Key to authenticate to Grafana, if not empty, Grafana output is enabled
- **GRAFANA_DASHBOARDID**: annotations are scoped to a specific dashboard. Optionnal.
- **GRAFANA_PANELID**: annotations are scoped to a specific panel. Optionnal.
- **GRAFANA_ALLFIELDSASTAGS**: if true, all custom fields are added as tags (default: false)
- **GRAFANA_MUTUALTLS**: if true, checkcert flag will be ignored (server cert will always be checked)
- **GRAFANA_CHECKCERT**: check if ssl certificate of the output is valid (default: true)
- **GRAFANA_MINIMUMPRIORITY**: minimum priority of event for using this output, order is
  `emergency|alert|critical|error|warning|notice|informational|debug or "" (default)`
- **GRAFANA_CUSTOMHEADERS** : a list of comma separated custom headers to add,
  syntax is "key:value,key:value"
- **GRAFANAONCALL_WEBHOOKURL**: if not empty, Grafana OnCall output is enabled
- **GRAFANAONCALL_MUTUALTLS**: if true, checkcert flag will be ignored (server cert will always be checked)
- **GRAFANAONCALL_CHECKCERT**: check if ssl certificate of the output is valid (default: true)
- **GRAFANAONCALL_MINIMUMPRIORITY**: minimum priority of event for using this output, order is
  `emergency|alert|critical|error|warning|notice|informational|debug or "" (default)`
- **GRAFANAONCALL_CUSTOMHEADERS** : a list of comma separated custom headers to add,
  syntax is "key:value,key:value"
- **YANDEX_ACCESSKEYID** : Yandex Access Key Id
- **YANDEX_SECRETACCESSKEY** : Yandex Secret Access Key
- **YANDEX_REGION**: Yandex region (default: ru-central-1)
- **YANDEX_S3_ENDPOINT**: Yandex storage endpoint (default: https://storage.yandexcloud.net)
- **YANDEX_S3_BUCKET**: Yandex storage, bucket name
- **YANDEX_S3_PREFIX**: name of prefix, keys will have format: s3://<bucket>/<prefix>/YYYY-MM-DD/YYYY-MM-DDTHH:mm:ss.s+01:00.json
- **YANDEX_S3_MINIMUMPRIORITY**: # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug
- **YANDEX_DATASTREAMS_ENDPOINT**: Yandex Data Streams endpoint (default: https://yds.serverless.yandexcloud.net)
- **YANDEX_DATASTREAMS_STREAMNAME**: Stream name in format /${region}/${folder_id}/${ydb_id}/${stream_name}
- **YANDEX_DATASTREAMS_MINIMUMPRIORITY**: # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug
- **SYSLOG_HOST**: Syslog Host, if not empty, Syslog output is enabled
- **SYSLOG_PORT**: Syslog endpoint port number
- **SYSLOG_PROTOCOL**: Syslog transport protocol. It can be either "tcp" or "udp" (default: tcp)
- **SYSLOG_FORMAT**: Syslog payload format. It can be either "json" or "cef" (default: json)
- **SYSLOG_MINIMUMPRIORITY**: minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default: "debug")
- **POLICYREPORT_ENABLED**: if true policyreport output is enabled (default: `false`)
- **POLICYREPORT_KUBECONFIG**: Kubeconfig file to use (only if falcosidekick is running outside the cluster)
- **POLICYREPORT_MINIMUMPRIORITY**: events with priority above this are mapped to fail in PolicyReport summary and lower that those are mapped to warn 
- **POLICYREPORT_MAXEVENTS**: the max number of events that can be per report (default: 1000)
- **POLICYREPORT_PRUNEBYPRIORITY**: if true; the events with lowest severity are pruned first, in FIFO order (default: `false`)
- **MQTT_BROKER**: broker address, can start with `tcp://` or `ssl://`, if not empty, MQTT output is enabled
- **MQTT_TOPIC**: topic for messages (default: `falco/events`)
- **MQTT_QOS**: QOS for messages (default: `0`)
- **MQTT_RETAINED**: if `true`, messages are retained (default: `false`)
- **MQTT_USER**: user if the authentication is enabled in the broker
- **MQTT_PASSWORD**: password if the authentication is enabled in the broker
- **MQTT_CHECKCERT**: check if ssl certificate of the output is valid (default: `true`)
- **MQTT_PRUNEBYPRIORITY**: if true; the events with lowest severity are pruned first, in FIFO order (default: `false`)
- **ZINC_HOSTPORT**: http://{domain or ip}:{port}, if not empty, ZincSearch output is enabled
- **ZINC_INDEX**: index (default: falco)
- **ZINC_USERNAME**: this username to authenticate to ZincSearch (default: "")
- **ZINC_PASSWORD**: use this password to authenticate to ZincSearch (default: "")
- **ZINC_CHECKCERT**: if ssl certificate of the output is valid (default: true)
- **ZINC_MINIMUMPRIORITY**: minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug
- **GOTIFY_HOSTPORT**: http://{domain or ip}:{port}, if not empty, Gotify output is enabled
- **GOTIFY_TOKEN**: API Token
- **GOTIFY_FORMAT**: Format of the messages (plaintext, markdown, json) (default: markdown)
- **GOTIFY_CHECKCERT**: check if ssl certificate of the output is valid (default: true)
- **GOTIFY_MINIMUMPRIORITY**: minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
- **TEKTON_EVENTLISTENER** : EventListener address, if not empty, Tekton output is enabled
- **TEKTON_MINIMUMPRIORITY** : minimum priority of event for using this output,
order is
`emergency|alert|critical|error|warning|notice|informational|debug or "" (default)`
- **TEKTON_CHECKCERT** : check if ssl certificate of the output is valid (default:
`true`)
- **SPYDERBAT_ORGUID**: Organization to send output to, if not empty, Spyderbat output is enabled
- **SPYDERBAT_APIKEY**: Spyderbat API key with access to the organization
- **SPYDERBAT_APIURL**: Spyderbat API url (default: "https://api.spyderbat.com")
- **SPYDERBAT_SOURCE**: Spyderbat source ID, max 32 characters (default: "falcosidekick")
- **SPYDERBAT_SOURCEDESCRIPTION**: Spyderbat source description and display name if not empty, max 256 characters
- **SPYDERBAT_MINIMUMPRIORITY**: minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
- **TIMESCALEDB_HOST**: TimescaleDB host, if not empty, TImescaleDB output is enabled
- **TIMESCALEDB_PORT**: TimescaleDB port (default: 5432)
- **TIMESCALEDB_USER**: Username to authenticate with TimescaleDB (default: postgres)
- **TIMESCALEDB_PASSWORD**: Password to authenticate with TimescaleDB (default: postgres)
- **TIMESCALEDB_DATABASE**: TimescaleDB database used
- **TIMESCALEDB_HYPERTABLENAME**: Hypertable to store data events (default: falco_events) See TimescaleDB setup for more info
- **TIMESCALEDB_MINIMUMPRIORITY**: minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
- **REDIS_ADDRESS**: Redis host, if not empty, Redis output is enabled (example: localhost:6379)
- **REDIS_PASSWORD**: Password to authenticate with Redis (default: "")
- **REDIS_DATABASE**: Redis database number (default: 0)
- **REDIS_STORAGE**: Redis storage type: hashmap or list (default: "list")
- **REDIS_Key**: Redis storage key name for hashmap, list(default: "falco")
- **REDIS_MINIMUMPRIORITY**: minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
- **TELEGRAM_TOKEN**: telegram bot authentication token
- **TELEGRAM_CHATID**: telegram Identifier of the shared chat
- **TELEGRAM_CHECKCERT**: check if ssl certificate of the output is valid (default: true)
- **TELEGRAM_MINIMUMPRIORITY**: minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
- **N8N_ADDRESS**: N8N address, if not empty, N8N output is enabled
- **N8N_USER**: Password to authenticate with N8N in basic auth
- **N8N_PASSWORD**: Header Auth Value to authenticate with N8N
- **N8N_CHECKCERT**: check if ssl certificate of the output is valid (default: true)
- **N8N_MINIMUMPRIORITY**: minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
- **OPENOBSERVE_HOSTPORT** : Elasticsearch http://host:port, if not `empty`,
  OpenObserve is _enabled_
- **OPENOBSERVE_ORGANIZATIONNAME** : Organization name (default: default)
- **OPENOBSERVE_STREAMNAME** : Stream name (default: falco)
- **OPENOBSERVE_MINIMUMPRIORITY** : minimum priority of event for using this
  output, order is
  `emergency|alert|critical|error|warning|notice|informational|debug or "" (default)`
  `monthly`, `annually`, `none`
- **OPENOBSERVE_MUTUALTLS** : enable mutual tls authentication for this output (default:
  `false`)
- **OPENOBSERVE_CHECKCERT** : check if ssl certificate of the output is valid (default:
  `true`)
- **OPENOBSERVE_USERNAME** : use this username to authenticate to OpenObserve if the
  username is not empty (default: "")
- **OPENOBSERVE_PASSWORD** : use this password to authenticate to OpenObserve if the
  password is not empty (default: "")
- **OPENOBSERVE_CUSTOMHEADERS** : a list of comma separated custom headers to add,
  syntax is "key:value,key:value"
- **DYNATRACE_APITOKEN** : Dynatrace API token with the "logs.ingest" scope, more info : https://dt-url.net/8543sda, if not empty, Dynatrace output is enabled
- **DYNATRACE_APIURL** : Dynatrace API url, use https://ENVIRONMENTID.live.dynatrace.com/api for Dynatrace SaaS and https://YOURDOMAIN/e/ENVIRONMENTID/api for Dynatrace Managed, more info : https://www.dynatrace.com/support/help/get-started/monitoring-environment/environment-id
- **DYNATRACE_CHECKCERT** : check if ssl certificate of the output is valid (default: `true`)
- **DYNATRACE_MINIMUMPRIORITY** : minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)

#### Slack/Rocketchat/Mattermost/Googlechat Message Formatting

The `SLACK_MESSAGEFORMAT` environment variable and `slack.messageformat` YAML
value accept a [Go template](https://golang.org/pkg/text/template/) which can be
used to format the text of a slack alert. These templates are evaluated on the
JSON data from each Falco event - the following fields are available:

| Template Syntax                              | Description                                                                                                                                                        |
| -------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `{{ .Output }}`                              | A formatted string from Falco describing the event.                                                                                                                |
| `{{ .Priority }}`                            | The priority of the event, as a string.                                                                                                                            |
| `{{ .Rule }}`                                | The name of the rule that generated the event.                                                                                                                     |
| `{{ .Time }}`                                | The timestamp when the event occurred.                                                                                                                             |
| `{{ index .OutputFields \"<field name>\" }}` | A map of additional optional fields emitted depending on the event. These may not be present for every event, in which case they expand to the string `<no value>` |

Go templates also support some basic methods for text manipulation which can be
used to improve the clarity of alerts - see the documentation for details.

## Handlers

Different URI (handlers) are available :

- `/` : main and default handler, your falco config must be configured to use it
- `/ping` : you will get a `pong` as answer, useful to test if falcosidekick is
  running and its port is opened (for healthcheck purpose for example). This
  endpoint is deprecated and it will be removed in `3.0.0`.
- `/healthz`: you will get a HTTP status code `200` response as answer, useful
  to test if falcosidekick is running and its port is opened (for healthcheck or
  purpose for example)
- `/test` : (for debug only) send a test event to all enabled outputs.
- `/debug/vars` : get statistics from daemon (in JSON format), it uses classic
  `expvar` package and some custom values are added
- `/metrics` : prometheus endpoint, for scraping metrics about events and
  `falcosidekick`

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

### StatsD / DogStatsD

The daemon is able to push its metrics to a StatsD/DogstatsD server. See
[Configuration](https://github.com/falcosecurity/falcosidekick#configuration)
section for how-to.

### AWS Policy example

When using the AWS output you will need to set the AWS keys with some
permissions to access the resources you selected to use, like `SQS`, `Lambda`,
`SNS` and `CloudWatchLogs`

#### CloudWatch Logs Sample Policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "cloudwacthlogs",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogStream",
        "logs:DescribeLogStreams",
        "logs:PutRetentionPolicy",
        "logs:PutLogEvents"
      ],
      "Resource": "*"
    }
  ]
}
```

#### SQS Sample Policy

```json
{
  "Version": "2012-10-17",
  "Id": "sqs",
  "Statement": [
    {
      "Sid": "sendMessage",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "sqs:SendMessage",
      "Resource": "arn:aws:sqs:*:111122223333:queue1"
    }
  ]
}
```

#### SNS Sample Policy

```json
{
  "Version": "2012-10-17",
  "Id": "sns",
  "Statement": [
    {
      "Sid": "publish",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "sns:Publish",
      "Resource": "arn:aws:sqs:*:111122223333:queue1"
    }
  ]
}
```

#### Lambda Sample Policy

```json
{
  "Version": "2012-10-17",
  "Id": "lambda",
  "Statement": [
    {
      "Sid": "invoke",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "lambda:InvokeFunction",
      "Resource": "*"
    }
  ]
}
```

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

## Examples

Run you daemon and try (from Falco's documentation) :

```bash
curl -XPOST "http://localhost:2801/" -d'{"output":"16:31:56.746609046: Error File below a known binary directory opened for writing (user=root command=touch /bin/hack file=/bin/hack)","hostname": "localhost", "priority":"Error","rule":"Write below binary dir","time":"2019-05-17T15:31:56.746609046Z", "output_fields": {"evt.time":1507591916746609046,"fd.name":"/bin/hack","proc.cmdline":"touch /bin/hack","user.name":"root"}}'
```

You should get :

### Slack

(SLACK_OUTPUTFORMAT="**all**")

![slack example](https://github.com/falcosecurity/falcosidekick/raw/master/imgs/slack.png)

(SLACK_OUTPUTFORMAT="**text**")

![slack no fields example](https://github.com/falcosecurity/falcosidekick/raw/master/imgs/slack_no_fields.png)

(SLACK_OUTPUTFORMAT="**fields**" and SLACK_MESSAGEFORMAT="**Alert :
rule \*{{ .Rule }}\* triggered by
user \*{{ index .OutputFields \"user.name\" }}\***")

![slack message format example](https://github.com/falcosecurity/falcosidekick/raw/master/imgs/slack_fields_messageformat.png)

### Mattermost

![mattermost example](https://github.com/falcosecurity/falcosidekick/raw/master/imgs/mattermost.png)

### Teams

(TEAMS_OUTPUTFORMAT="**all**")

![teams example](https://github.com/falcosecurity/falcosidekick/raw/master/imgs/teams.png)

(TEAMS_OUTPUTFORMAT="**text**")

![teams facts only](https://github.com/falcosecurity/falcosidekick/raw/master/imgs/teams_text.png)

### Datadog

_(Tip: filter on `sources: falco`)_

![datadog example](https://github.com/falcosecurity/falcosidekick/raw/master/imgs/datadog.png)

### AlertManager

![alertmanager example](https://github.com/falcosecurity/falcosidekick/raw/master/imgs/alertmanager.png)

### Elasticsearch (with Kibana)

![kibana example](https://github.com/falcosecurity/falcosidekick/raw/master/imgs/kibana.png)

### Influxdb

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

### Loki (with Grafana)

![loki example](https://github.com/falcosecurity/falcosidekick/raw/master/imgs/loki.png)

### AWS SQS

![aws sqs example](https://github.com/falcosecurity/falcosidekick/raw/master/imgs/aws_sqs.png)

### SMTP

(SMTP_OUTPUTFORMAT="**html**")

![smtp html example](https://github.com/falcosecurity/falcosidekick/raw/master/imgs/smtp_html.png)

(SMTP_OUTPUTFORMAT="**text**")

![smtp plaintext example](https://github.com/falcosecurity/falcosidekick/raw/master/imgs/smtp_plaintext.png)

### Opsgenie

![opsgenie example](https://github.com/falcosecurity/falcosidekick/raw/master/imgs/opsgenie.png)

### Discord

![discord example](https://github.com/falcosecurity/falcosidekick/raw/master/imgs/discord.png)

### Google Chat

(GOOGLECHAT_OUTPUTFORMAT="**all**")

![google chat example](https://github.com/falcosecurity/falcosidekick/raw/master/imgs/google_chat_no_fields.png)

(GOOGLECHAT_OUTPUTFORMAT="**text**")

![google chat text example](https://github.com/falcosecurity/falcosidekick/raw/master/imgs/google_chat_example.png)

### Dynatrace

![Dynatrace example](https://github.com/falcosecurity/falcosidekick/raw/master/imgs/dynatrace.png)

## Installing Policy Report Custom Resource Definition (CRD)

Information about how to find and install the CRD for the reports can be found [here](https://github.com/kubernetes-sigs/wg-policy-prototypes/tree/master/policy-report#installing). Installation of the Policy Report Custom Resource Definition (CRD) is a prerequisite for using Policy Report output.


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
