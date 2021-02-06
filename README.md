# Falcosidekick

![falcosidekick](https://github.com/falcosecurity/falcosidekick/raw/master/imgs/falcosidekick_color.png)

![release](https://flat.badgen.net/github/release/falcosecurity/falcosidekick/latest?color=green)
![last commit](https://flat.badgen.net/github/last-commit/falcosecurity/falcosidekick)
![licence](https://flat.badgen.net/badge/license/MIT/blue)
![docker pulls](https://flat.badgen.net/docker/pulls/falcosecurity/falcosidekick?icon=docker)
[![falcosidekick](https://circleci.com/gh/falcosecurity/falcosidekick.svg?style=shield)](https://circleci.com/gh/falcosecurity/falcosidekick)

## Description

A simple daemon for enhancing available outputs for
[Falco](https://sysdig.com/opensource/falco/). It takes a falco's event and
forwards it to different outputs.

It works as a single endpoint for as many as you want `falco` instances :

![falco_with_falcosidekick](https://github.com/falcosecurity/falcosidekick/raw/master/imgs/falco_with_falcosidekick.png)

## Outputs

Currently available outputs are :

- [**Slack**](https://slack.com)
- [**Rocketchat**](https://rocket.chat/)
- [**Mattermost**](https://mattermost.com/)
- [**Teams**](https://products.office.com/en-us/microsoft-teams/group-chat-software)
- [**Datadog**](https://www.datadoghq.com/)
- [**Discord**](https://www.discord.com/)
- [**AlertManager**](https://prometheus.io/docs/alerting/alertmanager/)
- [**Elasticsearch**](https://www.elastic.co/)
- [**Loki**](https://grafana.com/oss/loki)
- [**NATS**](https://nats.io/)
- [**STAN (NATS Streaming)**](https://docs.nats.io/nats-streaming-concepts/intro)
- [**Influxdb**](https://www.influxdata.com/products/influxdb-overview/)
- [**AWS Lambda**](https://aws.amazon.com/lambda/features/)
- [**AWS SQS**](https://aws.amazon.com/sqs/features/)
- [**AWS SNS**](https://aws.amazon.com/sns/features/)
- [**AWS CloudWatchLogs**](https://aws.amazon.com/cloudwatch/features/)
- **SMTP** (email)
- [**Opsgenie**](https://www.opsgenie.com/)
- [**StatsD**](https://github.com/statsd/statsd) (for monitoring of
  `falcosidekick`)
- [**DogStatsD**](https://docs.datadoghq.com/developers/dogstatsd/?tab=go) (for
  monitoring of `falcosidekick`)
- **Webhook**
- [**Azure Event Hubs**](https://azure.microsoft.com/en-in/services/event-hubs/)
- [**Prometheus**](https://prometheus.io/) (for both events and monitoring of
  `falcosidekick`)
- [**GCP PubSub**](https://cloud.google.com/pubsub)
- [**Google Chat**](https://workspace.google.com/products/chat/)
- [**Apache Kafka**](https://kafka.apache.org/)
- [**PagerDuty**](https://pagerduty.com/)
- [**Kubeless**](https://kubeless.io/)
- [**WebUI**](https://github.com/falcosecurity/falcosidekick-ui) (a Web UI for displaying latest events in real time)

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
#listenport: 2801 # port to listen for daemon (default: 2801)
debug: false # if true all outputs will print in stdout the payload they send (default: false)
customfields: # custom fields are added to falco events
  Akey: "AValue"
  Bkey: "BValue"
  Ckey: "CValue"
checkCert: true # check if ssl certificate of the output is valid (default: true)

slack:
  webhookurl: "" # Slack WebhookURL (ex: https://hooks.slack.com/services/XXXX/YYYY/ZZZZ), if not empty, Slack output is enabled
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

mattermost:
  webhookurl: "" # Mattermost WebhookURL (ex: http://XXXX/hooks/YYYY), if not empty, Mattermost output is enabled
  #footer: "" # Mattermost footer
  #icon: "" # Mattermost icon (avatar)
  #username: "" # Mattermost username (default: Falcosidekick)
  outputformat: "all" # all (default), text, fields
  minimumpriority: "debug" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
  # messageformat: "Alert : rule **{{ .Rule }}** triggered by user **{{ index .OutputFields \"user.name\" }}**" # a Go template to format Mattermost Text above Attachment, displayed in addition to the output from `MATTERMOST_OUTPUTFORMAT`, see [Slack Message Formatting](#slack-message-formatting) in the README for details. If empty, no Text is displayed before Attachment.

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

elasticsearch:
  # hostport: "" # http://{domain or ip}:{port}, if not empty, Elasticsearch output is enabled
  # index: "falco" # index (default: falco)
  # type: "event"
  # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
  # suffix: "daily" # date suffix for index rotation : daily (default), monthly, annually, none

influxdb:
  # hostport: "" # http://{domain or ip}:{port}, if not empty, Influxdb output is enabled
  # database: "falco" # Influxdb database (default: falco)
  # user: "" # user to use if auth is enabled in Influxdb
  # password: "" # pasword to use if auth is enabled in Influxdb
  # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)

loki:
  # hostport: "" # http://{domain or ip}:{port}, if not empty, Loki output is enabled
  # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)

nats:
  # hostport: "" # nats://{domain or ip}:{port}, if not empty, NATS output is enabled
  # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)

stan:
  # hostport: "" # nats://{domain or ip}:{port}, if not empty, STAN output is enabled
  # clusterid: "" # Cluster name, if not empty, STAN output is enabled
  # clientid: "" # Client ID, if not empty, STAN output is enabled
  # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)

aws:
  # accesskeyid: "" # aws access key (optional if you use EC2 Instance Profile)
  # secretaccesskey: "" # aws secret access key (optional if you use EC2 Instance Profile)
  # region : "" # aws region (optional if you use EC2 Instance Profile)
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

smtp:
  # hostport: "" # host:port address of SMTP server, if not empty, SMTP output is enabled
  # user: "" # user to access SMTP server
  # password: "" # password to access SMTP server
  # from: "" # Sender address (mandatory if SMTP output is enabled)
  # to: "" # comma-separated list of Recipident addresses, can't be empty (mandatory if SMTP output is enabled)
  # outputformat: "" # html (default), text
  # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)

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
  # customHeaders: # Custom headers to add in POST, useful for Authentication
  #   key: value
  # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)

azure:
  # eventHub:
  # name: "" # The name of the Hub, if not empty, EventHub output is enabled
  # namespace: "" # The name of the space the Hub is part of
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

googlechat:
  webhookurl: "" # Google Chat WebhookURL (ex: https://chat.googleapis.com/v1/spaces/XXXXXX/YYYYYY), if not empty, Google Chat output is enabled
  # outputformat: "" # all (default), text
  # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
  messageformat: 'Alert : rule *{{ .Rule }}* triggered by user *{{ index
    .OutputFields "user.name" }}*' # a Go template to format Google Chat Text above Attachment, displayed in addition to the output from `GOOGLECHAT_OUTPUTFORMAT`, see [Slack Message Formatting](#slack-message-formatting) in the README for details. If empty, no Text is displayed before Attachment.

kafka:
  hostport: "" # Apache Kafka Host:Port (ex: localhost:9092). Defaults to port 9092 if no port is specified after the domain, if not empty, Kafka output is enabled
  topic: "" # Name of the topic, if not empty, Kafka output is enabled
  # partition: 0 # Partition number of the topic.
  # minimumpriority: "debug" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)

pagerduty:
  # apikey: # Pagerduty API Key, if not empty, Pagerduty output is enabled
  service: "" # Service to create an incident (mandatory)
  assignee: "" # A list of comma separated users to assign. Cannot be provided if pagerduty.escalationpolicy is already specified.
  escalationpolicy: "" # Escalation policy to assign. Cannot be provided if pagerduty.escalationpolicy is already specified
  # minimumpriority: "debug" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)

kubeless:
  function: "" # Name of Kubeless function, if not empty, Kubeless is enabled
  namespace: "" # Namespace of Kubeless function (mandatory)
  port: 8080 # Port of service of Kubeless function
  kubeconfig: "~/.kube/config" # Kubeconfig file to use (only if falcoside is running outside the cluster)
  # minimumpriority: "debug" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)

webui:
  url: "" # WebUI URL, if not empty, WebUI output is enabled
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

- **LISTENPORT** : port to listen for daemon (default: `2801`)
- **DEBUG** : if _true_ all outputs will print in stdout the payload they send
  (default: false)
- **CUSTOMFIELDS** : a list of comma separated custom fields to add to falco
  events, syntax is "key:value,key:value"
- **CHECKCERT**: check if ssl certificate of the output is valid (default:
  `true`)
- **SLACK_WEBHOOKURL** : Slack Webhook URL (ex:
  https://hooks.slack.com/services/XXXX/YYYY/ZZZZ), if not `empty`, Slack output
  is _enabled_
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
- **ELASTICSEARCH_HOSTPORT** : Elasticsearch http://host:port, if not `empty`,
  Elasticsearch is _enabled_
- **ELASTICSEARCH_INDEX** : Elasticsearch index (default: falco)
- **ELASTICSEARCH_TYPE** : Elasticsearch document type (default: event)
- **ELASTICSEARCH_MINIMUMPRIORITY** : minimum priority of event for using this
  output, order is
  `emergency|alert|critical|error|warning|notice|informational|debug or "" (default)`
- **ELASTICSEARCH_SUFFIX** : date suffix for index rotation : `daily` (default),
  `monthly`, `annually`, `none`
- **INFLUXDB_HOSTPORT** : Influxdb http://host:port, if not `empty`, Influxdb is
  _enabled_
- **INFLUXDB_DATABASE** : Influxdb database (default: falco)
- **INFLUXDB_USER** : user to use if auth is enabled in Influxdb
- **INFLUXDB_PASSWORD** : user to use if auth is enabled in Influxdb
- **INFLUXDB_MINIMUMPRIORITY** : minimum priority of event for using this
  output, order is
  `emergency|alert|critical|error|warning|notice|informational|debug or "" (default)`
- **LOKI_HOSTPORT** : Loki http://host:port, if not `empty`, Loki is _enabled_
- **LOKI_MINIMUMPRIORITY** : minimum priority of event for using this output,
  order is
  `emergency|alert|critical|error|warning|notice|informational|debug or "" (default)`
- **NATS_HOSTPORT** : NATS "nats://host:port", if not `empty`, NATS is _enabled_
- **NATS_MINIMUMPRIORITY** : minimum priority of event for using this output,
  order is
  `emergency|alert|critical|error|warning|notice|informational|debug or "" (default)`
- **STAN_HOSTPORT** : NATS "nats://host:port", if not `empty`, STAN is _enabled_
- **STAN_CLUSTERID** : Cluster name, if not `empty`, STAN is _enabled_
- **STAN_CLIENTID** : Client ID to use, if not `empty`, STAN is _enabled_
- **STAN_MINIMUMPRIORITY** : minimum priority of event for using this output,
  order is
  `emergency|alert|critical|error|warning|notice|informational|debug or "" (default)`
- **AWS_ACCESSKEYID** : AWS Access Key Id (optional if you use EC2 Instance
  Profile)
- **AWS_SECRETACCESSKEY** : AWS Secret Access Key (optional if you use EC2
  Instance Profile)
- **AWS_REGION** : AWS Region (optional if you use EC2 Instance Profile)
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
- **SMTP_HOSTPORT** : "host:port" address of SMTP server, if not empty, SMTP
  output is _enabled_
- **SMTP_USER** : user to access SMTP server
- **SMTP_PASSWORD** : password to access SMTP server
- **SMTP_FROM** : Sender address (mandatory if SMTP output is enabled)
- **SMTP_TO** : comma-separated list of Recipident addresses, can't be empty
  (mandatory if SMTP output is enabled)
- **SMTP_OUTPUTFORMAT** : "" # html (default), text
- **SMTP_MINIMUMPRIORITY** : minimum priority of event for using this output,
  order is
  `emergency|alert|critical|error|warning|notice|informational|debug or "" (default)`
- **OPSGENIE_APIKEY** : Opsgenie API Key, if not empty, Opsgenie output is
  _enabled_
- **OPSGENIE_REGION** : (us|eu) region of your domain (default is 'us')
- **OPSGENIE_MINIMUMPRIORITY** : minimum priority of event for using this
  output, order is
  `emergency|alert|critical|error|warning|notice|informational|debug or "" (default)`
- **STATSD_FORWARDER**: The address for the StatsD forwarder, in the form
  http://host:port, if not empty StatsD is _enabled_
- **STATSD_NAMESPACE**: A prefix for all metrics (default: "falcosidekick.")
- **DOGSTATSD_FORWARDER**: The address for the DogStatsD forwarder, in the form
  http://host:port, if not empty DogStatsD is _enabled_
- **DOGSTATSD_NAMESPACE**: A prefix for all metrics (default: falcosidekick."")
- **DOGSTATSD_TAGS**: A comma-separated list of tags to add to all metrics
- **WEBHOOK_ADDRESS** : Webhook address, if not empty, Webhook output is
  _enabled_
- **WEBHOOK_CUSTOMHEADERS** : a list of comma separated custom headers to add,
  syntax is "key:value,key:value"
- **WEBHOOK_MINIMUMPRIORITY** : minimum priority of event for using this output,
  order is
  `emergency|alert|critical|error|warning|notice|informational|debug or "" (default)`
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
- **KAFKA_HOSTPORT**: The Host:Port of the Kafka (ex: localhost:9092), if not
  empty, Kafka is _enabled_
- **KAFKA_TOPIC**: The name of the Kafka topic
- **KAFKA_PARTITION**: The number of the Kafka partition
- **KAFKA_MINIMUMPRIORITY**: minimum priority of event for using this output,
  order is
  `emergency|alert|critical|error|warning|notice|informational|debug or "" (default)`
- **PAGERDUTY_APIKEY**: Pagerduty API Key, if not empty, Pagerduty output is
  _enabled_
- **PAGERDUTY_SERVICE**: Service to create an incident (mandatory)
- **PAGERDUTY_ASSIGNEE**: A list of comma separated users to assign. Cannot be
  provided if `PAGERDUTY_ESCALATION_POLICY` is already specified. If not empty,
  Pagerduty is _enabled_
- **PAGERDUTY_ESCALATION_POLICY**: Escalation policy to assign. Cannot be
  provided if `PAGERDUTY_ASSIGNEE` is already specified.If not empty, Pagerduty
  is _enabled_
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
- **WEBUI_URL** : WebUI URL, if not empty, WebUI output is 
  _enabled_

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

## Examples

Run you daemon and try (from falco's documentation) :

```bash
curl "http://localhost:2801/" -d'{"output":"16:31:56.746609046: Error File below a known binary directory opened for writing (user=root command=touch /bin/hack file=/bin/hack)","priority":"Error","rule":"Write below binary dir","time":"2019-05-17T15:31:56.746609046Z", "output_fields": {"evt.time":1507591916746609046,"fd.name":"/bin/hack","proc.cmdline":"touch /bin/hack","user.name":"root"}}'
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
