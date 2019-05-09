# Changelog

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