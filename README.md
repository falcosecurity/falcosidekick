# Falcosidekick

![falcosidekick](https://github.com/Issif/falcosidekick/raw/master/imgs/falcosidekick.png)

![release](https://flat.badgen.net/github/release/Issif/falcosidekick/latest?color=green) ![last commit](https://flat.badgen.net/github/last-commit/Issif/falcosidekick) ![licence](https://flat.badgen.net/badge/license/MIT/blue) ![docker pulls](https://flat.badgen.net/docker/pulls/issif/falcosidekick?icon=docker)

## Description

A simple daemon to help you with falco's outputs (https://sysdig.com/opensource/falco/). It takes a falco's event and forwards it to different outputs.

## Outputs

Currently available outputs are :

* **Slack**
* **Datadog**
* **AlertManager**

## Usage

Run the daemon as any other daemon in your architecture (systemd, k8s daemonset, swarm service, ...)

### With docker

```bash
docker run -d -p 2801:2801 -e SLACK_WEBHOOK_URL=XXXX -e DATADOG_API_KEY=XXXX issif/falcosidekick
```

### Falco's config

Add this (adapted to your environment) in your *falco.yaml* :

```bash
json_output: true
json_include_output_property: true
program_output:
  enabled: true
  keep_alive: false
  program: "curl -d @- localhost:2801/"
```

### Env variables

Configuration of the daemon is made by *env vars* :

* **LISTEN_PORT** : port to listen for daemon (default: 2801)
* **SLACK_WEBHOOK_URL** : Slack WebhookURL (ex: https://hooks.slack.com/services/XXXX/YYYY/ZZZZ), if not `empty`, Slack output is *enabled*
* **SLACK_FOOTER** : Slack footer
* **SLACK_ICON** : Slack icon (avatar)
* **SLACK_OUTPUT_FORMAT** : `all` (default), `text` (only text is displayed in Slack), `fields` (only fields are displayed in Slack)
* **DATADOG_API_KEY** : Datadog API Key, if not `empty`, Datadog output is *enabled*
* **ALERTMANAGER_HOST_PORT** : AlertManager host:port, if not `empty`, AlertManager is *enabled*
* **DEBUG** : if *true* all outputs will print in stdout the payload they send

## Handlers

Different URI (handlers) are available :

* `/` : main and default handler, your falco config must be configured to use it
* `/ping` : you will get a  `pong` as answer, useful to test if falcosidekick is running and its port is opened (for healthcheck purpose for example)
* `/test` : (for debug only) send a test event to all enabled outputs.

## Logs

All logs are sent to `stdout`.

```bash
2019/05/10 14:32:06 [INFO] : Enabled Outputs : Slack Datadog
```

## Examples

Run you daemon and try (from falco's documentation) :

```bash
curl "http://localhost:2801/" -d'{"output":"16:31:56.746609046: Error File below a known binary directory opened for writing (user=root command=touch /bin/hack file=/bin/hack)","priority":"Error","rule":"Write below binary dir","time":"2017-10-09T23:31:56.746609046Z", "output_fields": {"evt.time":1507591916746609046,"fd.name":"/bin/hack","proc.cmdline":"touch /bin/hack","user.name":"root"}}'
```

You should get :

### Slack

(SLACK_OUTPUT_FORMAT="all")
![slack example](https://github.com/Issif/falcosidekick/raw/master/imgs/slack.png)
(SLACK_OUTPUT_FORMAT="fields")
![slack no fields example](https://github.com/Issif/falcosidekick/raw/master/imgs/slack_no_fields.png)

### Datadog

*(Tip: filter on `sources: falco`)*
![datadog example](https://github.com/Issif/falcosidekick/raw/master/imgs/datadog.png)

### AlertManager

![alertmanager example](https://github.com/Issif/falcosidekick/raw/master/imgs/alertmanager.png)

## Development

### Build

```bash
go build
```

### Test & Coverage

```bash
go test ./outputs -count=1 -cover -v
```

## Author

Thomas Labarussias (https://github.com/Issif)