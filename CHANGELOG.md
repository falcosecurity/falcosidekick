# Changelog

## 2.28.0 - 2023-07-18
#### New
- New output: **Redis** ([PR#396](https://github.com/falcosecurity/falcosidekick/pull/396) thanks to [@pandyamarut](https://github.com/pandyamarut))
- New output: **Telegram** ([PR#431](https://github.com/falcosecurity/falcosidekick/pull/431) thanks to [@zufardhiyaulhaq](https://github.com/zufardhiyaulhaq))
- New output: **N8N** ([PR#462](https://github.com/falcosecurity/falcosidekick/pull/462))
- New output: **Grafana OnCall** ([PR#470](https://github.com/falcosecurity/falcosidekick/pull/470))
- New output: **OpenObserve** ([PR#509](https://github.com/falcosecurity/falcosidekick/pull/509))

#### Enhancement
- Add `output` in the description annotation for `AlertManager` output ([PR#341](https://github.com/falcosecurity/falcosidekick/pull/478))
- Allow to set the http method for `Webhook` output ([PR#399](https://github.com/falcosecurity/falcosidekick/pull/399))
- Add `hostname` as prometheus label ([PR#420](https://github.com/falcosecurity/falcosidekick/pull/420) thanks to [@Lowaiz](https://github.com/Lowaiz))
- Allow to replace the brackets ([PR#421](https://github.com/falcosecurity/falcosidekick/pull/421))
- Allow to set custom http headers for `Loki`, `Elasticsearch` and `Grafana` outputs ([PR#428](https://github.com/falcosecurity/falcosidekick/pull/428))
- Add `hostname`, `tags`, `custom` and `templated fields` for `TimescaleDB` output ([PR#438](https://github.com/falcosecurity/falcosidekick/pull/438) thanks to [@hileef](https://github.com/hileef))
- Allow to set thresholds for the dropped events in `AlertManager` ouput ([PR#439](https://github.com/falcosecurity/falcosidekick/pull/439) thanks to [@Lowaiz](https://github.com/Lowaiz))
- Match the `priority` with `AlertManager` severity label ([PR#440](https://github.com/falcosecurity/falcosidekick/pull/440) thanks to [@Lowaiz](https://github.com/Lowaiz))
- Add `rolearn` and `externalid` for the assume role for `AWS` outputs ([PR#494](https://github.com/falcosecurity/falcosidekick/pull/494))
- Allow to set the `region` for `PagerDuty` output ([PR#500](https://github.com/falcosecurity/falcosidekick/pull/500))
- Add TLS option + rewrite send method for the `SMTP` output ([PR#502](https://github.com/falcosecurity/falcosidekick/pull/502))
- Add attributes to `GCP PubSub` messages ([PR#505](https://github.com/falcosecurity/falcosidekick/pull/505) thanks to [@annadorottya](https://github.com/annadorottya))
- Add option for TLS and mTLS for the server ([PR#508](https://github.com/falcosecurity/falcosidekick/pull/508) thanks to [@annadorottya](https://github.com/annadorottya))
- Add setting to auto create the `Kafka` topic ([PR#554](https://github.com/falcosecurity/falcosidekick/pull/554))
- Add option to deploy a HTTP only server for specific endpoints ([PR#565](https://github.com/falcosecurity/falcosidekick/pull/565) thanks to [@annadorottya](https://github.com/annadorottya))
- Support multiple bootstrap servers for `Kafka` output ([PR#571](https://github.com/falcosecurity/falcosidekick/pull/571) thanks to [@ibice](https://github.com/ibice))
- Add option for TLS for `Kafka` output ([PR#574](https://github.com/falcosecurity/falcosidekick/pull/574))

#### Fix
- Fix error handling in `AWS Security Lake` output ([PR#390](https://github.com/falcosecurity/falcosidekick/pull/390))
- Fix breaking brackets in `AWS SNS` messages ([PR#419](https://github.com/falcosecurity/falcosidekick/pull/419))
- Fix setting name for the table of `TimescaleDB` output ([PR#426](https://github.com/falcosecurity/falcosidekick/pull/426) thanks to [@alika](https://github.com/alika))
- Fix cardinality issue with prometheus labels ([PR#427](https://github.com/falcosecurity/falcosidekick/pull/427))
- Fix panic when assert output fields which are nil ([PR#429](https://github.com/falcosecurity/falcosidekick/pull/429))
- Fix dependencies for `Wavefront` output ([PR#432](https://github.com/falcosecurity/falcosidekick/pull/432))
- Fix key pattern for `AWS Security Lake` output ([PR#447](https://github.com/falcosecurity/falcosidekick/pull/447))
- Fix default settings for `Telegram` output ([PR#495](https://github.com/falcosecurity/falcosidekick/pull/495) thanks to [@schfkt](https://github.com/schfkt))
- Fix URL generation for `Spyderbat` output ([PR#506](https://github.com/falcosecurity/falcosidekick/pull/506) thanks to [@bc-sb](https://github.com/bc-sb))
- Fix nil values in `Spyderbat` output ([PR#527](https://github.com/falcosecurity/falcosidekick/pull/527) thanks to [@spider-guy](https://github.com/spider-guy))
- Fix duplicated headers in `SMTP` output ([PR#528](https://github.com/falcosecurity/falcosidekick/pull/528) thanks to [@apsega](https://github.com/apsega))
- Fix missing trim for names and values of labels for `AlertManager` output ([PR#563](https://github.com/falcosecurity/falcosidekick/pull/563) thanks to [@Lowaiz](https://github.com/Lowaiz))
- Fix missing returned errors for `Kafka` output ([PR#573](https://github.com/falcosecurity/falcosidekick/pull/573))

## 2.27.0 - 2022-12-13
#### New
- New output: **Yandex Data Streams** ([PR#336](https://github.com/falcosecurity/falcosidekick/pull/336) thanks to [@preved911](https://github.com/preved911))
- New output: **Node-Red** ([PR#337](https://github.com/falcosecurity/falcosidekick/pull/337))
- New output: **MQTT** ([PR#338](https://github.com/falcosecurity/falcosidekick/pull/338))
- Templated fields: custom fields generated with Go templates ([PR#350](https://github.com/falcosecurity/falcosidekick/pull/350))
- New output: **Zincsearch** ([PR#360](https://github.com/falcosecurity/falcosidekick/pull/360))
- New output: **Gotify** ([PR#362](https://github.com/falcosecurity/falcosidekick/pull/362))
- New output: **Spyderbat** ([PR#368](https://github.com/falcosecurity/falcosidekick/pull/368) thanks to [@spyder-kyle](https://github.com/spyder-kyle))
- New output: **Tekton** ([PR#371](https://github.com/falcosecurity/falcosidekick/pull/371))
- New output: **TimescaleDB** ([PR#378](https://github.com/falcosecurity/falcosidekick/pull/378) thanks to [@jagretti](https://github.com/jagretti))
- New output: **AWS Security Lake** ([PR#387](https://github.com/falcosecurity/falcosidekick/pull/387))

#### Enhancement
- `SMTP` output now uses any SASL auth mechanism ([PR#341](https://github.com/falcosecurity/falcosidekick/pull/341) thanks to [@Lowaiz](https://github.com/Lowaiz))
- Bind `Policy Reports` to Namespace by `ownerReference` ([PR#346](https://github.com/falcosecurity/falcosidekick/pull/346))
- Add extra labels and annotations for `AlertManager` payloads ([PR#347](https://github.com/falcosecurity/falcosidekick/pull/347) thanks to [@Lowaiz](https://github.com/Lowaiz))
- Update default type for `Elasticsearch` documents ([PR#349](https://github.com/falcosecurity/falcosidekick/pull/349))
- Support env vars in custom fields ([PR#353](https://github.com/falcosecurity/falcosidekick/pull/353))
- Update format + default endpoint for `Loki` output ([PR#356](https://github.com/falcosecurity/falcosidekick/pull/356))
- Determine resource names + owner ref for `Policy Reports` ([PR#358](https://github.com/falcosecurity/falcosidekick/pull/358))
- Update `Influxdb` output to use API Token and /api/v2 endpoint ([PR#359](https://github.com/falcosecurity/falcosidekick/pull/359))
- Allow to override the `Slack` channel ([PR#366](https://github.com/falcosecurity/falcosidekick/pull/366))
- Add From, To and Date headers in `SMTP` payload ([PR#364](https://github.com/falcosecurity/falcosidekick/pull/364))
- Improve the check of the payload from `Falco`, it allows now to have an empty output ([PR#372](https://github.com/falcosecurity/falcosidekick/pull/372))
- Allow to set user and api key for `Loki` output for `Grafana Logs` ([PR#379](https://github.com/falcosecurity/falcosidekick/pull/379)
- Add `hostname` in json payload for all outputs ([PR#383](https://github.com/falcosecurity/falcosidekick/pull/383) thanks to [@Lowaiz](https://github.com/Lowaiz))
- Add SASL authentication for `Kafka` output ([PR#385](https://github.com/falcosecurity/falcosidekick/pull/385) thanks to [@Lowaiz](https://github.com/Lowaiz)) and [@lyoung-confluent](https://github.com/lyoung-confluent))
- Support CEF format for `Syslog` output ([PR#386](https://github.com/falcosecurity/falcosidekick/pull/386))
- Allow to disable STS check for `AWS` output ([PR#387](https://github.com/falcosecurity/falcosidekick/pull/387))

#### Fix
- Fix `priority` label was replaced by `source` in `AlertManager` payload ([PR#340](https://github.com/falcosecurity/falcosidekick/pull/340) thanks to [@tks98](https://github.com/tks98))
- Fix missing cert checks + fix inverted logic to use them in codebase ([PR#345](https://github.com/falcosecurity/falcosidekick/pull/345))
- Fix race condition when headers are added to POST requests ([PR#380](https://github.com/falcosecurity/falcosidekick/pull/380) thanks to [@bc-sb](https://github.com/bc-sb))

## 2.26.0 - 2022-06-18
#### Enhancement
- Add `expiresafter` for *AlertManager* output ([PR#323](https://github.com/falcosecurity/falcosidekick/pull/323) thanks to [@anushkamittal20](https://github.com/anushkamittal20))
- Add `extralabels` for *Loki* and *Prometheus* outputs which allow to set fields to use as labels additionally to `rule`, `source`, `priority`, `tags` and `customfields` ([PR#327](https://github.com/falcosecurity/falcosidekick/pull/327))
#### Fix
- Fix *Panic* for Prometheus metrics when `customfields` are set ([PR#333](https://github.com/falcosecurity/falcosidekick/pull/333))

## 2.25.0 - 2022-05-12
#### New
- New output: **Policy Report** ([PR#256](https://github.com/falcosecurity/falcosidekick/pull/256) thanks to [@anushkamittal20](https://github.com/anushkamittal20))
- New output: **Syslog** ([PR#272](https://github.com/falcosecurity/falcosidekick/pull/272) thanks to [@bdluca](https://github.com/bdluca))
- New output: **AWS Kinesis** ([PR#277](https://github.com/falcosecurity/falcosidekick/pull/277) thanks to [@gauravgahlot](https://github.com/gauravgahlot))
- New output: **Zoho Cliq** ([PR#301](https://github.com/falcosecurity/falcosidekick/pull/301) thanks to [@averni](https://github.com/averni))
- Images and Binaries for *arm* and *arm64* ([PR#288](https://github.com/falcosecurity/falcosidekick/pull/288))
- Sign artifacts with *cosign* ([PR#302](https://github.com/falcosecurity/falcosidekick/pull/302))
#### Enhancement
- Add CI steps to push images into AWS ECR ([PR#270](https://github.com/falcosecurity/falcosidekick/pull/270) thanks to [@maxgio92](https://github.com/maxgio92))
- Allow to choose API endpoint for *AlertManager* ([PR#282](https://github.com/falcosecurity/falcosidekick/pull/282) thanks to [@mathildeHermet](https://github.com/maxgiomathildeHermet92))
- Add label `priority` in *AlertManager* events ([PR#276](https://github.com/falcosecurity/falcosidekick/pull/276))
- Update Golang + GolangCI-Lint ([PR#289](https://github.com/falcosecurity/falcosidekick/pull/289) [PR#292](https://github.com/falcosecurity/falcosidekick/pull/292))
- Add version info ([PR#290](https://github.com/falcosecurity/falcosidekick/pull/290))
- Update image base to alpine 3.15 ([PR#291](https://github.com/falcosecurity/falcosidekick/pull/291))
- Increase CircleCI timeout ([PR#293](https://github.com/falcosecurity/falcosidekick/pull/293))
- Support *IRSA* for AWS authentication ([PR#295](https://github.com/falcosecurity/falcosidekick/pull/295) thanks to [@VariableExp0rt](https://github.com/VariableExp0rt))
- Add *tenant* for *Loki* output ([PR#308](https://github.com/falcosecurity/falcosidekick/pull/308) thanks to [@JGodin-C2C](https://github.com/JGodin-C2C))
- Upgrade endpoint for *Loki* ([PR#309](https://github.com/falcosecurity/falcosidekick/pull/309) thanks to [@JGodin-C2C](https://github.com/JGodin-C2C))
- Add `tags` and `source` in events for all outputs ([PR#310](https://github.com/falcosecurity/falcosidekick/pull/310))
- Add `custom_fields` to *Prometheus* series ([PR#314](https://github.com/falcosecurity/falcosidekick/pull/314) thanks to [@LyvingInSync](https://github.com/LyvingInSync))
- Update CircleCI jobs ([PR#316](https://github.com/falcosecurity/falcosidekick/pull/316))
#### Fix
- Fix *OpsGenie* output when keys have "." ([PR#287](https://github.com/falcosecurity/falcosidekick/pull/287))
- Fix typo in README ([PR#299](https://github.com/falcosecurity/falcosidekick/pull/299) thanks to [@oleg-nenashev](https://github.com/oleg-nenashev))
- Fix *GCS* writer not closed ([PR#312](https://github.com/falcosecurity/falcosidekick/pull/312) thanks to [@Milkshak3s](https://github.com/Milkshak3s))

## 2.24.0 - 2021-08-13
#### New
- New output: **Grafana** ([PR#254](https://github.com/falcosecurity/falcosidekick/pull/254))
- New output: **Fission** ([PR#255](https://github.com/falcosecurity/falcosidekick/pull/255) thanks to [@gauravgahlot](https://github.com/gauravgahlot))
- New output: **Yandex Cloud S3** ([PR#261](https://github.com/falcosecurity/falcosidekick/pull/261) thanks to [@nar3k](https://github.com/nar3k))
- New output: **Kafka REST** ([PR#263](https://github.com/falcosecurity/falcosidekick/pull/263) thanks to [@dirien](https://github.com/dirien))
#### Enhancement
- Set header `x-amz-acl` to `bucket-owner-full-control` for output `AWS S3` ([PR#264](https://github.com/falcosecurity/falcosidekick/pull/264) thanks to [@Kaizhe](https://github.com/Kaizhe))
- Docker image is now available on [`AWS ECR Public Gallery`](https://gallery.ecr.aws/falcosecurity/falcosidekick) ([PR#265](https://github.com/falcosecurity/falcosidekick/pull/265) thanks to [@maxgio92](https://github.com/maxgio92))

## 2.23.1 - 2021-06-23
#### Fix
- Fix memory leak with `AddHeaders` method ([PR#252](https://github.com/falcosecurity/falcosidekick/pull/252) thanks to [@distortedsignal](https://github.com/distortedsignal))

## 2.23.0 - 2021-06-23
#### New
- New output: **Wavefront** ([PR#229](https://github.com/falcosecurity/falcosidekick/pull/229) thanks to [@rikatz](https://github.com/rikatz))
- New output: **GCP Cloud Functions** ([PR#241](https://github.com/falcosecurity/falcosidekick/pull/241))
- New output: **GCP Cloud Run** ([PR#243](https://github.com/falcosecurity/falcosidekick/pull/243))
- Allow MutualTLS for some outputs ([PR#231](https://github.com/falcosecurity/falcosidekick/pull/231) thanks to [@jasiam](https://github.com/jasiam))
- Allow *Workload identity* for *GCP* output ([PR#235](https://github.com/falcosecurity/falcosidekick/pull/235) thanks to [@cartyc](https://github.com/cartyc))
- Add basic auth for *Elasticsearch* output ([PR#245](https://github.com/falcosecurity/falcosidekick/pull/245) thanks to [@distortedsignal](https://github.com/distortedsignal))
#### Enhancement
- Reorder fields in *Slack*t, *RocketChat* and *Mattermost* outputs + sort `customer_fields` alphabetically ([PR#226](https://github.com/falcosecurity/falcosidekick/pull/226))
- Set default values for *OpenFaas* output ([PR#232](https://github.com/falcosecurity/falcosidekick/pull/232))
- Re-use session for *AWS* output instead of deprecated `session.New()` ([PR#238](https://github.com/falcosecurity/falcosidekick/pull/238) thanks to [@dchoy](https://github.com/dchoy))
- Reorganize management of headers for outputs ([PR#245](https://github.com/falcosecurity/falcosidekick/pull/245) thanks to [@distortedsignal](https://github.com/distortedsignal))
#### Fix
- Fix init of **DogstatsD** output ([PR#227](https://github.com/falcosecurity/falcosidekick/pull/227))
- Remove duplicated logs + fix some of prefixes ([PR#228](https://github.com/falcosecurity/falcosidekick/pull/228))
- Fif *S3* output when "Default encryption" setting is disabled ([PR#242](https://github.com/falcosecurity/falcosidekick/pull/242) thanks to [@Kaizhe](https://github.com/Kaizhe))

## 2.22.0 - 2021-04-06
#### New
- New output: **AWS S3** ([PR#195](https://github.com/falcosecurity/falcosidekick/pull/195) thanks to [@evalsocket](https://github.com/evalsocket))
- New output: **GCP Storage** ([PR#202](https://github.com/falcosecurity/falcosidekick/pull/202) thanks to [@evalsocket](https://github.com/evalsocket))
- New output: **RabbitMQ** ([PR#210](https://github.com/falcosecurity/falcosidekick/pull/210) thanks to [@evalsocket](https://github.com/evalsocket))
- New output: **OpenFaas** ([PR#208](https://github.com/falcosecurity/falcosidekick/pull/208) thanks to [@developper-guy](https://github.com/developper-guy))
#### Enhancement
- Use higher level Writer api for **Kafka** ([PR#206](https://github.com/falcosecurity/falcosidekick/pull/206) thanks to [@zemek](https://github.com/zemek))
- Reorder *imports* to follow good practices ([PR#205](https://github.com/falcosecurity/falcosidekick/pull/205))
- Prevent misleading error message when *CUSTOMFIELDS* env var is set ([PR#201](https://github.com/falcosecurity/falcosidekick/pull/201) thanks to [@zemek](https://github.com/zemek))
- Use *Events v2* API for **PagerDuty** output ([PR#200](https://github.com/falcosecurity/falcosidekick/pull/200) thanks to [@caWhite](https://github.com/caWhite))
#### Fix
- Fix *outputformat* when using fields or text in **Slack** output ([PR#204](https://github.com/falcosecurity/falcosidekick/pull/204))
- Fix HTML template for **SMTP** output ([PR#199](https://github.com/falcosecurity/falcosidekick/pull/199))

## 2.21.0 - 2021-02-12
#### New
- New output: **Cloud Events** ([PR#169](https://github.com/falcosecurity/falcosidekick/pull/169) thanks to [@n3wscott](https://github.com/n3wscott))
- New output: **WebUI** ([PR#180](https://github.com/falcosecurity/falcosidekick/pull/180))
#### Enhancement
- Include numeric values for `Alertmanager` outputs ([PR#177](https://github.com/falcosecurity/falcosidekick/pull/177) thanks to to [@alsm](https://github.com/alsm))
- Add `listenaddress` option ([PR#187](https://github.com/falcosecurity/falcosidekick/pull/187) thanks to to [@alsm](https://github.com/alsm))
#### Fix
- Fix spelling typos in README ([PR#175](https://github.com/falcosecurity/falcosidekick/pull/175) thanks to to [@princespaghetti](https://github.com/princespaghetti))
- Fix several `gosec` issues ([PR#179](https://github.com/falcosecurity/falcosidekick/pull/179) thanks to to [@alsm](https://github.com/alsm))
- Fix label values with quotes for `Loki` ([PR#182](https://github.com/falcosecurity/falcosidekick/pull/182))

## 2.20.0 - 2021-01-12
#### New
- New output: **STAN (NATS Streaming)** ([PR#135](https://github.com/falcosecurity/falcosidekick/pull/135))
- New output: **PagerDuty** ([PR#164](https://github.com/falcosecurity/falcosidekick/pull/164))
- New output: **Kubeless** ([PR#170](https://github.com/falcosecurity/falcosidekick/pull/170))
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
- New output: **Apache Kafka** ([PR#124](https://github.com/falcosecurity/falcosidekick/pull/124) thanks to [@KeisukeYamashita](https://github.com/KeisukeYamashita))
- New output: **Cloudwatch Logs** ([PR#127](https://github.com/falcosecurity/falcosidekick/pull/127) thanks to [@cpanato](https://github.com/cpanato))
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
- New output: **Google Chat** ([PR#107](https://github.com/falcosecurity/falcosidekick/pull/107) thanks to [@KeisukeYamashita](https://github.com/KeisukeYamashita))
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
- New output: **GCP PubSub** ([PR#97](https://github.com/falcosecurity/falcosidekick/pull/97) thanks to [@IanRobertson-wpe](https://github.com/IanRobertson-wpe))
#### Enhancement
- Better instructions for install with `Helm` ([PR#95](https://github.com/falcosecurity/falcosidekick/pull/95) thanks to [@pyaillet](https://github.com/pyaillet))

## 2.16.0 - 2020-10-29
#### New
- Custom Headers can be set for `Webhook` output ([PR#92](https://github.com/falcosecurity/falcosidekick/pull/92))
#### Enhancement
- Enable of `CircleCI` for unit tests

## 2.15.0 - 2020-10-27
#### New
- New output: **AWS SNS** ([PR#84](https://github.com/falcosecurity/falcosidekick/pull/84))
- A `prometheus` exporter is now available for all metrics
#### Enhancement
- Reduce cardinality of alerts by grouping them for `AlertManager` ([PR#79](https://github.com/falcosecurity/falcosidekick/pull/79) thanks to [@epcim](https://github.com/epcim))
#### Fix
- Fix unsupported chars in a label name for `AlertManager` ([PR#78](https://github.com/falcosecurity/falcosidekick/pull/78) thanks to [@epcim](https://github.com/epcim))
#### Note
The Helm chart has been migrated to [falcosecurity/charts](https://github.com/falcosecurity/charts/tree/master/falcosidekick), the official repository chart of `falco` organization. You can now install it from [artifacthub.io](https://artifacthub.io/packages/helm/falcosecurity/falcosidekick).

## 2.14.0 - 2020-08-10
#### New
- New output: **Azure Event Hubs** ([PR#66](https://github.com/falcosecurity/falcosidekick/pull/66) thanks to [@arminc](https://github.com/arminc))
- New output: **Discord** ([PR#61](https://github.com/falcosecurity/falcosidekick/pull/61) thanks to [@nibalizer](https://github.com/nibalizer))
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
- New output: **Rocketchat**
- New output: **Mattermost**

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
- New output: **Webhook**
- New output: **DogStatsD**
- New metrics : *running goroutines*, *number of used CPU*
#### Enhancement
- :boom: Standardization of metric names (to be consistent between *expar* and *(Dog)StatsD*)
- :boom: New namespace for metrics (*inputs*), will be used for future *inputs* (*fifo*, *gRPC*)
#### Fix
- *StatsD* implementation worked only with *DogStatsD* ([issue #49](https://github.com/falcosecurity/falcosidekick/issues/49))
- Fix *panic* when payload from *Falco* is empty

## 2.10.0 - 2019-10-22
#### New
- New output: **StatsD** ([PR#43](https://github.com/falcosecurity/falcosidekick/pull/40) thanks to [@actgardner](https://github.com/actgardner))


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
- New output: **Opsgenie**
#### Enhancement
- New avatar : with colors and squared
#### Fix
- Duplicated entries when events have non-string fields ([PR#38](https://github.com/falcosecurity/falcosidekick/pull/38) thanks to [@actgardner](https://github.com/actgardner))

## 2.8.0 - 2019-09-11
#### New
- New output: **NATS**

## 2.7.2 - 2019-08-28
#### Enhancement
- All referencies to previous repository are replaced, falcosidekick is now in falcosecurity organization

## 2.7.1 - 2019-08-28
#### Enhancement
- Update of Dockerfile : golang 1.12 + alpine 3.10

## 2.7.0 - 2019-08-27
#### New
- New output: **Loki**

## 2.6.0 - 2019-08-26
#### New
- New output: **SMTP** (email)

## 2.5.0 - 2019-08-12
#### New
- New output: **AWS Lambda**
- New output: **AWS SQS** ([issue #5](https://github.com/falcosecurity/falcosidekick/issues/5))
- New output: **Teams** ([issue #30](https://github.com/falcosecurity/falcosidekick/issues/30))
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
- New output: **Influxdb** ([issue #4](https://github.com/falcosecurity/falcosidekick/issues/4))
#### Fix
- Panic happened when trying to add `customfields` but falco event hadn't

## 2.1.0 - 2019-06-12
#### New
- Custom fields can be added to falco events (see [README](https://github.com/falcosecurity/falcosidekick/blob/master/README.md)) ([PR#26](https://github.com/falcosecurity/falcosidekick/pull/26) thanks to [@zetaab](https://github.com/zetaab))
#### Fix
- Fix `Slack.Output` in config.go ([PR#24](https://github.com/falcosecurity/falcosidekick/pull/24) thanks to [@SweetOps](https://github.com/SweetOps))

## 2.0.0 - 2019-05-23
#### New
- New output: **Elasticsearch** ([issue #14](https://github.com/falcosecurity/falcosidekick/issues/14))
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
- New output: **Alert Manager**
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
