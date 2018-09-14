<p align="center">
    <img src="falcosidekick.png" width="30%"/>
</p>

# Falcosidekick
A simple daemon to help you with falco's outputs.

It takes output from falco and can forward it to :
* Slack
* Datadog

# Usage

Run the daemon as any other daemon in your architecture (systemd, k8s daemonset, ...)

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

* **LISTEN_PORT** : port to listen for daemon
* **SLACK_TOKEN** : slack url + token (ex: https://hooks.slack.com/services/XXXX/YYYY/ZZZZ)
* **DATADOG_TOKEN** : datadog token

# Examples

Run you daemon and try (from falco's documentation) :
```
curl "http://localhost:2801/" -d'{"output":"16:31:56.746609046: Error File below a known binary directory opened for writing (user=root command=touch /bin/hack file=/bin/hack)","priority":"Error","rule":"Write below binary dir","time":"2017-10-09T23:31:56.746609046Z", "output_fields": {"evt.time":1507591916746609046,"fd.name":"/bin/hack","proc.cmdline":"touch /bin/hack","user.name":"root"}}'
```

You should get :

* **Slack** :

![slack](https://raw.githubusercontent.com/issif/falcosidekick/slack.png)

* **Datadog** :
*(Tip: filter on `sources: falco`)*

![datadog](https://raw.githubusercontent.com/issif/falcosidekick/datadog.png)