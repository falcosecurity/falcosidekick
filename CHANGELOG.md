# Changelog

## 2.20.0 - 2021-01-12
#### New
- New output : **STAN (NATS Streaming)** ([PR#135](https://github.com/falcosecurity/falcosidekick/pull/135))
- New output : **PagerDuty** ([PR#164](https://github.com/falcosecurity/falcosidekick/pull/164))
- New output : **Kubeless** ([PR#170](https://github.com/falcosecurity/falcosidekick/pull/170))
#### Enhancement
- CI: clean filters ([PR#138](https://github.com/falcosecurity/falcosidekick/pull/138))
- Replace library for `Kafka` ([PR#139](https://github.com/falcosecurity/falcosidekick/pull/139))
- Re-align code for `NATS` output ([PR#159](https://github.com/falcosecurity/falcosidekick/pull/159))
- Add new endpoint `/healthz` ([PR#167](https://github.com/falcosecurity/falcosidekick/pull/167))
- Change the way to manage *Priority* ([PR#171](https://github.com/falcosecurity/falcosidekick/pull/171) thanks to [@n3wscott](https://github.com/n3wscott))
#### Fix
- Fix missing metrics for various outputs ([PR#145](https://github.com/falcosecurity/falcosidekick/pull/145), [PR#146](https://github.com/falcosecurity/falcosidekick/pull/146), [PR#147](https://github.com/falcosecurity/falcosidekick/pull/147), [PR#148](https://github.com/falcosecurity/falcosidekick/pull/148), [PR#149](https://github.com/falcosecurity/falcosidekick/pull/149), [PR#150](https://github.com/falcosecurity/falcosidekick/pull/150), [PR#151](https://github.com/falcosecurity/falcosidekick/pull/151), [PR#152](https://github.com/falcosecurity/falcosidekick/pull/152), [PR#153](https://github.com/falcosecurity/falcosidekick/pull/153), [PR#154](https://github.com/falcosecurity/falcosidekick/pull/154), [PR#155](https://github.com/falcosecurity/falcosidekick/pull/155), [PR#156](https://github.com/falcosecurity/falcosidekick/pull/156), [PR#157](https://github.com/falcosecurity/falcosidekick/pull/157), [PR#158](https://github.com/falcosecurity/falcosidekick/pull/158))

## 2.19.1 - 2020-12-02
#### Fix
- Fix dockerfile to build the new kafka output ([PR#56](https://github.com/falcosecurity/falcosidekick/pull/132) thanks to [@cpanato](https://github.com/cpanato))

## 2.19.0 - 2020-12-01
#### New
- New output : **Apache Kafka** ([PR#124](https://github.com/falcosecurity/falcosidekick/pull/124) thanks to [@KeisukeYamashita](https://github.com/KeisukeYamashita))
- New output : **Cloudwatch Logs** ([PR#127](https://github.com/falcosecurity/falcosidekick/pull/127) thanks to [@cpanato](https://github.com/cpanato))
#### Enhancement
- Bump Golang version to `1.15` ([PR#128](https://github.com/falcosecurity/falcosidekick/pull/128) thanks to [@KeisukeYamashita](https://github.com/KeisukeYamashita))
- Add a contributing document ([PR#123](https://github.com/falcosecurity/falcosidekick/pull/123) thanks to [@cpanato](https://github.com/cpanato))
- Add a `.dockerignore` for small images ([PR#126](https://github.com/falcosecurity/falcosidekick/pull/126) thanks to [@KeisukeYamashita](https://github.com/KeisukeYamashita))
- Refactor HTTP server handler ([PR#116](https://github.com/falcosecurity/falcosidekick/pull/116) thanks to [@KeisukeYamashita](https://github.com/KeisukeYamashita))
- Add test for `Discord` ([PR#117](https://github.com/falcosecurity/falcosidekick/pull/117) thanks to [@KeisukeYamashita](https://github.com/KeisukeYamashita))
#### Fix
- Fix Discord output's Prometheus metrics ([PR#118](https://github.com/falcosecurity/falcosidekick/pull/118) thanks to [@KeisukeYamashita](https://github.com/KeisukeYamashita))
- Fix `nil pointer` when `GCP` configuration is incorrect ([PR#130](https://github.com/falcosecurity/falcosidekick/pull/130))

## 2.18.0 - 2020-11-20
#### New
- New output : **Google Chat** ([PR#107](https://github.com/falcosecurity/falcosidekick/pull/107) thanks to [@KeisukeYamashita](https://github.com/KeisukeYamashita))
#### Enhancement
- Add test for `Mattermost` ([PR#99](https://github.com/falcosecurity/falcosidekick/pull/99) thanks to [@cpanato](https://github.com/cpanato))
- Add golangci lint ([PR#100](https://github.com/falcosecurity/falcosidekick/pull/100) thanks to [@cpanato](https://github.com/cpanato))
- Dependecies: update several deps ([PR#103](https://github.com/falcosecurity/falcosidekick/pull/103) thanks to [@cpanato](https://github.com/cpanato))
- clean a bit the `Circleci` config ([PR#106](https://github.com/falcosecurity/falcosidekick/pull/106) thanks to [@cpanato](https://github.com/cpanato))
- Use `testify` to check the test results ([PR#108](https://github.com/falcosecurity/falcosidekick/pull/108) [PR#112](https://github.com/falcosecurity/falcosidekick/pull/112) thanks to [@cpanato](https://github.com/cpanato))
- Refactor type assertion in output ([PR#110](https://github.com/falcosecurity/falcosidekick/pull/110) thanks to [@KeisukeYamashita](https://github.com/KeisukeYamashita))
- Add test for `Rocketchat` ([PR#113](https://github.com/falcosecurity/falcosidekick/pull/113) thanks to [@cpanato](https://github.com/cpanato))
#### Fix
- Fix stats for `Mattermost` ([PR#99](https://github.com/falcosecurity/falcosidekick/pull/99) thanks to [@cpanato](https://github.com/cpanato))

## 2.17.0 - 2020-11-13
#### New
- New output : **GCP PubSub** ([PR#97](https://github.com/falcosecurity/falcosidekick/pull/97) thanks to [@IanRobertson-wpe](https://github.com/IanRobertson-wpe))
#### Enhancement
- Better instructions for install with `Helm` ([PR#95](https://github.com/falcosecurity/falcosidekick/pull/95) thanks to [@pyaillet](https://github.com/pyaillet))

## 2.16.0 - 2020-10-29
#### New
- Custom Headers can be set for `Webhook` output ([PR#92](https://github.com/falcosecurity/falcosidekick/pull/92))
#### Enhancement
- Enable of `CircleCI` for unit tests

## 2.15.0 - 2020-10-27
#### New
- New output : **AWS SNS** ([PR#84](https://github.com/falcosecurity/falcosidekick/pull/84))
- A `prometheus` exporter is now available for all metrics
#### Enhancement
- Reduce cardinality of alerts by grouping them for `AlertManager` ([PR#79](https://github.com/falcosecurity/falcosidekick/pull/79) thanks to [@epcim](https://github.com/epcim))
#### Fix
- Fix unsupported chars in a label name for `AlertManager` ([PR#78](https://github.com/falcosecurity/falcosidekick/pull/78) thanks to [@epcim](https://github.com/epcim))
#### Note
The Helm chart has been migrated to [falcosecurity/charts](https://github.com/falcosecurity/charts/tree/master/falcosidekick), the official repository chart of `falco` organization. You can now install it from [artifacthub.io](https://artifacthub.io/packages/helm/falcosecurity/falcosidekick).

## 2.14.0 - 2020-08-10
#### New
- New output : **Azure Event Hubs** ([PR#66](https://github.com/falcosecurity/falcosidekick/pull/66) thanks to [@arminc](https://github.com/arminc))
- New output : **Discord** ([PR#61](https://github.com/falcosecurity/falcosidekick/pull/61) thanks to [@nibalizer](https://github.com/nibalizer))
#### Enhancement
- Cert validity of outputs can be disabled ([PR#74](https://github.com/falcosecurity/falcosidekick/pull/74))
- Golang 1.14 is now used for building the Docker image
- Displayed username can be override for **Slack**, **Mattermost** and **Rocketchat** ([PR#72](https://github.com/falcosecurity/falcosidekick/pull/72))
#### Fix
- Wrong port name was displayed as output of Helm chart
#### Note
This release is the last one with an Helm chart, the next ones will be in [Falco Charts repo](https://github.com/helm/charts)

## 2.13.0 - 2020-06-15
#### New
- New output : **Rocketchat**
- New output : **Mattermost**

# 2.12.3 - 2020-04-21
#### Enhancement
- Allow using Datadog EU site by specifying new variable **datadog.host**/**DATADOG_HOST** ([PR#59](https://github.com/falcosecurity/falcosidekick/pull/59) thanks to [@DrPhil](https://github.com/DrPhil))
- Docker Image is based now on last Golang and Alpine images

## 2.12.2 - 2020-04-21
#### Fix
- Typo in query to Datadog ([PR#58](https://github.com/falcosecurity/falcosidekick/pull/58) thanks to [@DrPhil](https://github.com/DrPhil))

## 2.12.1 - 2020-01-28
#### Fix
- Typo in SMTP output logs ([PR#56](https://github.com/falcosecurity/falcosidekick/pull/56) thanks to [@cartyc](https://github.com/cartyc))

## 2.12.0 - 2020-01-16
#### Enhancement
- Add Pod Security Policy to helm chart ([PR#54](https://github.com/falcosecurity/falcosidekick/pull/54) thanks to [@czunker](https://github.com/czunker))

## 2.11.1 - 2020-01-06
#### Fix
- Wrong value reference for Elasticsearch output in deployment.yaml

## 2.11.0 - 2019-11-13
#### New
- New output : **Webhook**
- New output : **DogStatsD**
- New metrics : *running goroutines*, *number of used CPU*
#### Enhancement
- :boom: Standardization of metric names (to be consistent between *expar* and *(Dog)StatsD*)
- :boom: New namespace for metrics (*inputs*), will be used for future *inputs* (*fifo*, *gRPC*)
#### Fix
- *StatsD* implementation worked only with *DogStatsD* ([issue #49](https://github.com/falcosecurity/falcosidekick/issues/49))
- Fix *panic* when payload from *Falco* is empty

## 2.10.0 - 2019-10-22
#### New
- New output : **StatsD** ([PR#43](https://github.com/falcosecurity/falcosidekick/pull/40) thanks to [@actgardner](https://github.com/actgardner))


## 2.9.3 - 2019-10-18
#### Fix
- Fix typo in priority check ([PR#42](https://github.com/falcosecurity/falcosidekick/pull/42) thanks to [@palmerabollo](https://github.com/palmerabollo))

## 2.9.2 - 2019-10-11
#### Enhancement
#### Fix
- Fix Opgenie config in helm template ([PR#41](https://github.com/falcosecurity/falcosidekick/pull/41) thanks to [@kamirendawkins](https://github.com/kamirendawkins))

## 2.9.1 - 2019-10-07
#### Enhancement
- Add formatted Text in Slack message ([PR#40](https://github.com/falcosecurity/falcosidekick/pull/40) thanks to [@actgardner](https://github.com/actgardner))

## 2.9.0 - 2019-10-04
#### New
- New output : **Opsgenie**
#### Enhancement
- New avatar : with colors and squared
#### Fix
- Duplicated entries when events have non-string fields ([PR#38](https://github.com/falcosecurity/falcosidekick/pull/38) thanks to [@actgardner](https://github.com/actgardner))

## 2.8.0 - 2019-09-11
#### New
- New output : **NATS**

## 2.7.2 - 2019-08-28
#### Enhancement
- All referencies to previous repository are replaced, falcosidekick is now in falcosecurity organization

## 2.7.1 - 2019-08-28
#### Enhancement
- Update of Dockerfile : golang 1.12 + alpine 3.10

## 2.7.0 - 2019-08-27
#### New
- New output : **Loki**

## 2.6.0 - 2019-08-26
#### New
- New output : **SMTP** (email)

## 2.5.0 - 2019-08-12
#### New
- New output : **AWS Lambda**
- New output : **AWS SQS** ([issue #5](https://github.com/falcosecurity/falcosidekick/issues/5))
- New output : **Teams** ([issue #30](https://github.com/falcosecurity/falcosidekick/issues/30))
- A github page has been created : https://falcosecurity.github.io/falcosidekick/

#### Enhancement
- Slack tests are now consistant (order of fields in JSON output wasn't always the same, tests failed sometimes for that)
- README : clean up of several typos

## 2.4.0 - 2019-06-26
#### Enhancement
- Elasticsearch : An index suffix can be set for rotation (see [README](https://github.com/falcosecurity/falcosidekick/blob/master/README.md)) ([issue #27](https://github.com/falcosecurity/falcosidekick/issues/27) thanks to [@ariguillegp](https://github.com/ariguillegp))

## 2.3.0 - 2019-06-17
#### New
- Falcosidekick can now be deployed with Helm (see [README](https://github.com/falcosecurity/falcosidekick/blob/master/README.md)) ([PR#25](https://github.com/falcosecurity/falcosidekick/pull/25) thanks to [@SweetOps](https://github.com/SweetOps))

## 2.2.0 - 2019-06-13
#### New
- A minimum priority for each output can be set
- New output : **Influxdb** ([issue #4](https://github.com/falcosecurity/falcosidekick/issues/4))
#### Fix
- Panic happened when trying to add `customfields` but falco event hadn't

## 2.1.0 - 2019-06-12
#### New
- Custom fields can be added to falco events (see [README](https://github.com/falcosecurity/falcosidekick/blob/master/README.md)) ([PR#26](https://github.com/falcosecurity/falcosidekick/pull/26) thanks to [@zetaab](https://github.com/zetaab))
#### Fix
- Fix `Slack.Output` in config.go ([PR#24](https://github.com/falcosecurity/falcosidekick/pull/24) thanks to [@SweetOps](https://github.com/SweetOps))

## 2.0.0 - 2019-05-23
#### New
- New output : **Elasticsearch** ([issue #14](https://github.com/falcosecurity/falcosidekick/issues/14))
- **New configuration method : we can now use a config file in YAML and/or env vars** (see *README*) ([issue #17](https://github.com/falcosecurity/falcosidekick/issues/17))
- New endpoint : `/debug/vars` gives access to Golang + Custom metrics (see *README*) ([issue #17](https://github.com/falcosecurity/falcosidekick/issues/17))
#### Enhancement
- Add a lot of unit tests for code coverage ([issue #17](https://github.com/falcosecurity/falcosidekick/issues/17))
- Some log outputs have been reformated
- :boom: Some env variables have been renamed again to match fields in YAML config files (*see README*)
#### Fix
- Panic are now catched to avoid crashes

## 1.1.0 - 2019-05-10
#### Enhancement
-  **All outputs use new generic methods (`NewClient()` + `Post()`), new output integration will be easier**
- :boom: some variables have been renamed to be relevant with their real names in API docs of Outputs
    - `DATADOG_TOKEN` **->** `DATADOG_API_KEY`
    - `SLACK_TOKEN` **->** `SLACK_WEBHOOK_URL`
#### Fix
- `/test` sends an event with a timestamp set at *now*

## 1.0.7 - 2019-05-09
#### Enhancement
- Change `SLACK_HIDE_FIELDS` for `SLACK_OUTPUT_FORMAT`, you can now choose how events are displayed in Slack

## 1.0.6 - 2019-05-09
#### New
- Add `SLACK_HIDE_FIELDS` env var, to enable concise output in Slack (fields are not displayed) ([issue #15](https://github.com/falcosecurity/falcosidekick/issues/15))
#### Enhancement
- Remove `/checkPayload` endpoint, not usefull anymore
- Change of how enabled/disabled outputs are printed in log (more concise view)
- Falco's payload is printed in log if `DEBUG=true`

## 1.0.5 - 2019-04-09
#### New
- Add a `/test` endpoint which sends a fake event to all enabled outputs
- Add a `DEBUG` env var, if enabled, payload for enabled outputs will be printed in stdout
#### Enhancement
- Reformate some logs outputs to be nicer
- Add a check on payload's body from falco to avoid to send empty's ones to outputs

## 1.0.4 - 2019-02-01
#### New
- Add of **go mod** ([PR#1](https://github.com/falcosecurity/falcosidekick/pull/9) thanks to [@perriea](https://github.com/perriea))
#### Enhancement
- Use of *go mod* is Dockerfile for build ([PR#1](https://github.com/falcosecurity/falcosidekick/pull/9) thanks to [@perriea](https://github.com/perriea))
- Add email maintener in Dockerfile ([PR#1](https://github.com/falcosecurity/falcosidekick/pull/9) thanks to [@perriea](https://github.com/perriea))

## 1.0.3 - 2019-01-30
#### New
- New output  : **Alert Manager**
#### Enhancement
- Add status of posts to Outputs in logs (stdout)

## 1.0.2 - 2018-10-10
#### Enhancement
- Update changelog
- Update README with new Slack Options + more info

## 1.0.1 - 2018-10-10
#### New
- New Slack Options : `SLACK_FOOTER`, `SLACK_ICON`
#### Enhancements
- New Slack Options : `SLACK_FOOTER`, `SLACK_ICON`
- Add output status in log to get those which are enabled
- Check of `LISTEN_PORT` in `init()` : port must be an integer between 1 and 65535
- Long string in slack field values are not splitten anymore
#### Fix
- Some log level tags were missing
- Fix cert errors in alpine ([PR#1](https://github.com/falcosecurity/falcosidekick/pull/1) thanks to [@palmerabollo](https://github.com/palmerabollo))

## 1.0.0 - 2018-10-10
- First tagged release
