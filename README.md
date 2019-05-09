![falcosidekick](https://github.com/Issif/falcosidekick/raw/master/imgs/falcosidekick.png)

![release](https://flat.badgen.net/github/release/Issif/falcosidekick/latest?color=green) ![last commit](https://flat.badgen.net/github/last-commit/Issif/falcosidekick) ![licence](https://flat.badgen.net/badge/license/MIT/blue) ![docker pulls](https://flat.badgen.net/docker/pulls/issif/falcosidekick?icon=docker)

# Falcosidekick
A simple daemon to help you with falco's outputs (https://sysdig.com/opensource/falco/). It takes a falco's event and forwards it to different outputs. 

# Outputs

Currently available outputs are :
* Slack
* Datadog
* AlertManager

# Usage

Run the daemon as any other daemon in your architecture (systemd, k8s daemonset, swarm service, ...)

## With docker
```
docker run -d -p 2801:2801 -e SLACK_TOKEN=XXXX -e DATADOG_TOKEN=XXXX issif/falcosidekick
```

## Falco's config

Add this (adapted to your environment) in your *falco.yaml* :
```
json_output: true
json_include_output_property: true
program_output:
  enabled: true
  keep_alive: false
  program: "curl -d @- localhost:2801"
```

## Env variables 

Configuration of the daemon is made by Env vars :

* **LISTEN_PORT** : port to listen for daemon (default: 2801)
* **SLACK_TOKEN** : Slack URL + token (ex: https://hooks.slack.com/services/XXXX/YYYY/ZZZZ), if not `empty`, Slack output is *enabled*
* **SLACK_FOOTER** : Slack footer
* **SLACK_ICON** : Slack icon (avatar)
* **SLACK_OUTPUT_FORMAT** : `all` (default), `text` (only text is displayed in Slack), `fields` (only fields are displayed in Slack)
* **DATADOG_TOKEN** : Datadog token, if not `empty`, Datadog output is *enabled*
* **ALERTMANAGER_HOST_PORT** : AlertManager host:port, if not `empty`, AlertManager is *enabled*
* **DEBUG** : if *true* all outputs will print in stdout the payload they send

# Handlers

Different URI (handlers) are available :

* `/` : main and default handler, your falco config must be configured to use it
* `/ping` : you will get a  `pong` as answer, useful to test if falcosidekick is running and its port is opened (for healthcheck purpose for example)
* `/test` : (for debug only) send a test event to all enabled outputs.

# Logs

All logs are sent to `stdout`.

```
2018/10/11 08:53:25 [INFO] : Outputs configuration : Slack=enabled, Datadog=disabled, Alertmanager=disabled
2018/10/11 08:53:25 [INFO] : Falco Sidekick is up and listening on port 2801
```

# Examples

Run you daemon and try (from falco's documentation) :
```
curl "http://localhost:2801/" -d'{"output":"16:31:56.746609046: Error File below a known binary directory opened for writing (user=root command=touch /bin/hack file=/bin/hack)","priority":"Error","rule":"Write below binary dir","time":"2017-10-09T23:31:56.746609046Z", "output_fields": {"evt.time":1507591916746609046,"fd.name":"/bin/hack","proc.cmdline":"touch /bin/hack","user.name":"root"}}'
```

You should get :

**Slack** :

![slack example](https://github.com/Issif/falcosidekick/raw/master/imgs/slack.png)
![slack no fields example](https://github.com/Issif/falcosidekick/raw/master/imgs/slack_no_fields.png)

**Datadog** :

*(Tip: filter on `sources: falco`)*
![datadog example](https://github.com/Issif/falcosidekick/raw/master/imgs/datadog.png)

**AlertManager** :

![alertmanager example](https://github.com/Issif/falcosidekick/raw/master/imgs/alertmanager.png)