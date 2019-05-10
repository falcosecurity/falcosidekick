# Changelog

## 1.10.0 - 2019-05-10
#### Enhancement
-  **all outputs use new generic methods (`NewClient()` + `Post()`), new output integration will be easier**
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
- Add `SLACK_HIDE_FIELDS` env var, to enable concise output in Slack (fields are not displayed) ([issue #15](https://github.com/Issif/falcosidekick/issues/15))
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
- Add of **go mod** ([PR#1](https://github.com/Issif/falcosidekick/pull/9) thanks to [@perriea](https://github.com/perriea))
#### Enhancement
- Use of *go mod* is Dockerfile for build ([PR#1](https://github.com/Issif/falcosidekick/pull/9) thanks to [@perriea](https://github.com/perriea))
- Add email maintener in Dockerfile ([PR#1](https://github.com/Issif/falcosidekick/pull/9) thanks to [@perriea](https://github.com/perriea))

## 1.0.3 - 2019-01-30
#### New
- new output  : **Alert Manager**
#### Enhancement
- add status of posts to Outputs in logs (stdout)

## 1.0.2 - 2018-10-10
#### Enhancement
- update changelog
- update README with new Slack Options + more info 

## 1.0.1 - 2018-10-10
#### New
- new Slack Options : `SLACK_FOOTER`, `SLACK_ICON`
#### Enhancements
- new Slack Options : `SLACK_FOOTER`, `SLACK_ICON`
- add output status in log to get those which are enabled
- check of `LISTEN_PORT` in `init()` : port must be an integer between 1 and 65535
- long string in slack field values are not splitten anymore
#### Fix
- some log level tags were missing
- fix cert errors in alpine ([PR#1](https://github.com/Issif/falcosidekick/pull/1) thanks to [@palmerabollo](https://github.com/palmerabollo))

## 1.0.0 - 2018-10-10
- First tagged release