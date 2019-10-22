# Changelog

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