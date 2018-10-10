![falcosidekick](https://github.com/Issif/falcosidekick/raw/master/imgs/falcosidekick.png)


# Falcosidekick
A simple daemon to help you with falco's outputs (https://sysdig.com/opensource/falco/). It takes a falco's event and forwards it to different outputs. 

# Outputs

Currently available outputs are :
* Slack
* Datadog

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
* **SLACK_TOKEN** : slack url + token (ex: https://hooks.slack.com/services/XXXX/YYYY/ZZZZ)
* **SLACK_FOOTER** : slack footer
* **SLACK_ICON** : slack icon (avatar)
* **DATADOG_TOKEN** : datadog token

# Handlers

Different URI (handlers) are available :

* `/` : main and default handler, your falco config must be configured to use it
* `/ping` : you will get a  `pong` as answer, useful to test if falcosidekick is running and its port is opened (for healthcheck purpose for example)
* `/checkpayload` : (for debug only) you will get in response the exact payload which has been received by falcosidekick (no notification are sent to ouputs)

# Logs

All logs are sent to `stdout`.

# Examples

Run you daemon and try (from falco's documentation) :
```
curl "http://localhost:2801/" -d'{"output":"16:31:56.746609046: Error File below a known binary directory opened for writing (user=root command=touch /bin/hack file=/bin/hack)","priority":"Error","rule":"Write below binary dir","time":"2017-10-09T23:31:56.746609046Z", "output_fields": {"evt.time":1507591916746609046,"fd.name":"/bin/hack","proc.cmdline":"touch /bin/hack","user.name":"root"}}'
```

You should get :

* **Slack** :
![slack example](https://github.com/Issif/falcosidekick/raw/master/imgs/slack.png)
* **Datadog** :
*(Tip: filter on `sources: falco`)*
![datadog example](https://github.com/Issif/falcosidekick/raw/master/imgs/datadog.png)
