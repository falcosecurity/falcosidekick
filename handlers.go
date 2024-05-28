// SPDX-License-Identifier: MIT OR Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strings"
	"text/template"
	"time"

	"github.com/falcosecurity/falcosidekick/types"
	"github.com/google/uuid"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

const testRule string = "Test rule"

// mainHandler is Falcosidekick main handler (default).
func mainHandler(w http.ResponseWriter, r *http.Request) {
	stats.Requests.Add("total", 1)
	nullClient.CountMetric("total", 1, []string{})

	if r.Body == nil {
		http.Error(w, "Please send a valid request body", http.StatusBadRequest)
		stats.Requests.Add("rejected", 1)
		promStats.Inputs.With(map[string]string{"source": "requests", "status": "rejected"}).Inc()
		nullClient.CountMetric("inputs.requests.rejected", 1, []string{"error:nobody"})

		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Please send with post http method", http.StatusBadRequest)
		stats.Requests.Add("rejected", 1)
		promStats.Inputs.With(map[string]string{"source": "requests", "status": "rejected"}).Inc()
		nullClient.CountMetric("inputs.requests.rejected", 1, []string{"error:nobody"})

		return
	}

	falcopayload, err := newFalcoPayload(r.Body)
	if err != nil || !falcopayload.Check() {
		http.Error(w, "Please send a valid request body", http.StatusBadRequest)
		stats.Requests.Add("rejected", 1)
		promStats.Inputs.With(map[string]string{"source": "requests", "status": "rejected"}).Inc()
		nullClient.CountMetric("inputs.requests.rejected", 1, []string{"error:invalidjson"})

		return
	}

	nullClient.CountMetric("inputs.requests.accepted", 1, []string{})
	stats.Requests.Add("accepted", 1)
	promStats.Inputs.With(map[string]string{"source": "requests", "status": "accepted"}).Inc()
	forwardEvent(falcopayload)
}

// pingHandler is a simple handler to test if daemon is UP.
func pingHandler(w http.ResponseWriter, r *http.Request) {
	// #nosec G104 nothing to be done if the following fails
	w.Write([]byte("pong\n"))
}

// healthHandler is a simple handler to test if daemon is UP.
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	// #nosec G104 nothing to be done if the following fails
	w.Write([]byte(`{"status": "ok"}`))
}

// testHandler sends a test event to all enabled outputs.
func testHandler(w http.ResponseWriter, r *http.Request) {
	r.Body = io.NopCloser(bytes.NewReader([]byte(`{"output":"This is a test from falcosidekick","priority":"Debug","hostname": "falcosidekick", "rule":"Test rule", "time":"` + time.Now().UTC().Format(time.RFC3339) + `","output_fields": {"proc.name":"falcosidekick","user.name":"falcosidekick"}, "tags":["test","example"]}`)))
	mainHandler(w, r)
}

func newFalcoPayload(payload io.Reader) (types.FalcoPayload, error) {
	var falcopayload types.FalcoPayload

	d := json.NewDecoder(payload)
	d.UseNumber()

	err := d.Decode(&falcopayload)
	if err != nil {
		return types.FalcoPayload{}, err
	}

	var customFields string
	if len(config.Customfields) > 0 {
		if falcopayload.OutputFields == nil {
			falcopayload.OutputFields = make(map[string]interface{})
		}
		for key, value := range config.Customfields {
			customFields += key + "=" + value + " "
			falcopayload.OutputFields[key] = value
		}
	}

	if falcopayload.Rule == "Test rule" {
		falcopayload.Source = "internal"
	}

	if falcopayload.Source == "" {
		falcopayload.Source = "syscalls"
	}

	falcopayload.UUID = uuid.New().String()

	var kn, kp string
	for i, j := range falcopayload.OutputFields {
		if j != nil {
			if i == "k8s.ns.name" {
				kn = j.(string)
			}
			if i == "k8s.pod.name" {
				kp = j.(string)
			}
		}
	}

	var templatedFields string
	if len(config.Templatedfields) > 0 {
		if falcopayload.OutputFields == nil {
			falcopayload.OutputFields = make(map[string]interface{})
		}
		for key, value := range config.Templatedfields {
			tmpl, err := template.New("").Parse(value)
			if err != nil {
				log.Printf("[ERROR] : Parsing error for templated field '%v': %v\n", key, err)
				continue
			}
			v := new(bytes.Buffer)
			if err := tmpl.Execute(v, falcopayload.OutputFields); err != nil {
				log.Printf("[ERROR] : Parsing error for templated field '%v': %v\n", key, err)
			}
			templatedFields += key + "=" + v.String() + " "
			falcopayload.OutputFields[key] = v.String()
		}
	}

	if len(falcopayload.Tags) != 0 {
		sort.Strings(falcopayload.Tags)
	}

	nullClient.CountMetric("falco.accepted", 1, []string{"priority:" + falcopayload.Priority.String()})
	stats.Falco.Add(strings.ToLower(falcopayload.Priority.String()), 1)
	promLabels := map[string]string{"rule": falcopayload.Rule, "priority": falcopayload.Priority.String(), "source": falcopayload.Source, "k8s_ns_name": kn, "k8s_pod_name": kp}
	if falcopayload.Hostname != "" {
		promLabels["hostname"] = falcopayload.Hostname
	} else {
		promLabels["hostname"] = "unknown"
	}

	for key, value := range config.Customfields {
		if regPromLabels.MatchString(key) {
			promLabels[key] = value
		}
	}
	for _, i := range config.Prometheus.ExtraLabelsList {
		promLabels[strings.ReplaceAll(i, ".", "_")] = ""
		for key, value := range falcopayload.OutputFields {
			if key == i && regPromLabels.MatchString(strings.ReplaceAll(key, ".", "_")) {
				switch value.(type) {
				case string:
					promLabels[strings.ReplaceAll(key, ".", "_")] = fmt.Sprintf("%v", value)
				default:
					continue
				}
			}
		}
	}
	promStats.Falco.With(promLabels).Inc()

	if config.BracketReplacer != "" {
		for i, j := range falcopayload.OutputFields {
			if strings.Contains(i, "[") {
				falcopayload.OutputFields[strings.ReplaceAll(strings.ReplaceAll(i, "]", ""), "[", config.BracketReplacer)] = j
				delete(falcopayload.OutputFields, i)
			}
		}
	}

	if config.OutputFieldFormat != "" && regOutputFormat.MatchString(falcopayload.Output) {
		outputElements := strings.Split(falcopayload.Output, " ")
		if len(outputElements) >= 3 {
			t := strings.TrimSuffix(outputElements[0], ":")
			p := cases.Title(language.English).String(falcopayload.Priority.String())
			o := strings.Join(outputElements[2:], " ")
			n := config.OutputFieldFormat
			n = strings.ReplaceAll(n, "<timestamp>", t)
			n = strings.ReplaceAll(n, "<priority>", p)
			n = strings.ReplaceAll(n, "<output>", o)
			n = strings.ReplaceAll(n, "<custom_fields>", strings.TrimSuffix(customFields, " "))
			n = strings.ReplaceAll(n, "<templated_fields>", strings.TrimSuffix(templatedFields, " "))
			n = strings.TrimSuffix(n, " ")
			n = strings.TrimSuffix(n, "( )")
			n = strings.TrimSuffix(n, "()")
			n = strings.TrimSuffix(n, " ")
			falcopayload.Output = n
		}
	}

	if len(falcopayload.String()) > 4096 {
		for i, j := range falcopayload.OutputFields {
			switch j.(type) {
			case string:
				if len(j.(string)) > 512 {
					k := j.(string)[:507] + "[...]"
					falcopayload.Output = strings.ReplaceAll(falcopayload.Output, j.(string), k)
					falcopayload.OutputFields[i] = k
				}
			}
		}
	}

	if config.Debug {
		log.Printf("[DEBUG] : Falco's payload : %v\n", falcopayload.String())
	}

	return falcopayload, nil
}

func forwardEvent(falcopayload types.FalcoPayload) {
	if config.Slack.WebhookURL != "" && (falcopayload.Priority >= types.Priority(config.Slack.MinimumPriority) || falcopayload.Rule == testRule) {
		go slackClient.SlackPost(falcopayload)
	}

	if config.Cliq.WebhookURL != "" && (falcopayload.Priority >= types.Priority(config.Cliq.MinimumPriority) || falcopayload.Rule == testRule) {
		go cliqClient.CliqPost(falcopayload)
	}

	if config.Rocketchat.WebhookURL != "" && (falcopayload.Priority >= types.Priority(config.Rocketchat.MinimumPriority) || falcopayload.Rule == testRule) {
		go rocketchatClient.RocketchatPost(falcopayload)
	}

	if config.Mattermost.WebhookURL != "" && (falcopayload.Priority >= types.Priority(config.Mattermost.MinimumPriority) || falcopayload.Rule == testRule) {
		go mattermostClient.MattermostPost(falcopayload)
	}

	if config.Teams.WebhookURL != "" && (falcopayload.Priority >= types.Priority(config.Teams.MinimumPriority) || falcopayload.Rule == testRule) {
		go teamsClient.TeamsPost(falcopayload)
	}

	if config.Datadog.APIKey != "" && (falcopayload.Priority >= types.Priority(config.Datadog.MinimumPriority) || falcopayload.Rule == testRule) {
		go datadogClient.DatadogPost(falcopayload)
	}

	if config.Discord.WebhookURL != "" && (falcopayload.Priority >= types.Priority(config.Discord.MinimumPriority) || falcopayload.Rule == testRule) {
		go discordClient.DiscordPost(falcopayload)
	}

	if config.Alertmanager.HostPort != "" && (falcopayload.Priority >= types.Priority(config.Alertmanager.MinimumPriority) || falcopayload.Rule == testRule) {
		go alertmanagerClient.AlertmanagerPost(falcopayload)
	}

	if config.Elasticsearch.HostPort != "" && (falcopayload.Priority >= types.Priority(config.Elasticsearch.MinimumPriority) || falcopayload.Rule == testRule) {
		go elasticsearchClient.ElasticsearchPost(falcopayload)
	}

	if config.Quickwit.HostPort != "" && (falcopayload.Priority >= types.Priority(config.Quickwit.MinimumPriority) || falcopayload.Rule == testRule) {
		go quickwitClient.QuickwitPost(falcopayload)
	}

	if config.Influxdb.HostPort != "" && (falcopayload.Priority >= types.Priority(config.Influxdb.MinimumPriority) || falcopayload.Rule == testRule) {
		go influxdbClient.InfluxdbPost(falcopayload)
	}

	if config.Loki.HostPort != "" && (falcopayload.Priority >= types.Priority(config.Loki.MinimumPriority) || falcopayload.Rule == testRule) {
		go lokiClient.LokiPost(falcopayload)
	}

	if config.SumoLogic.ReceiverURL != "" && (falcopayload.Priority >= types.Priority(config.SumoLogic.MinimumPriority) || falcopayload.Rule == testRule) {
		go sumologicClient.SumoLogicPost(falcopayload)
	}

	if config.Nats.HostPort != "" && (falcopayload.Priority >= types.Priority(config.Nats.MinimumPriority) || falcopayload.Rule == testRule) {
		go natsClient.NatsPublish(falcopayload)
	}

	if config.Stan.HostPort != "" && config.Stan.ClusterID != "" && config.Stan.ClientID != "" && (falcopayload.Priority >= types.Priority(config.Stan.MinimumPriority) || falcopayload.Rule == testRule) {
		go stanClient.StanPublish(falcopayload)
	}

	if config.AWS.Lambda.FunctionName != "" && (falcopayload.Priority >= types.Priority(config.AWS.Lambda.MinimumPriority) || falcopayload.Rule == testRule) {
		go awsClient.InvokeLambda(falcopayload)
	}

	if config.AWS.SQS.URL != "" && (falcopayload.Priority >= types.Priority(config.AWS.SQS.MinimumPriority) || falcopayload.Rule == testRule) {
		go awsClient.SendMessage(falcopayload)
	}

	if config.AWS.SNS.TopicArn != "" && (falcopayload.Priority >= types.Priority(config.AWS.SNS.MinimumPriority) || falcopayload.Rule == testRule) {
		go awsClient.PublishTopic(falcopayload)
	}

	if config.AWS.CloudWatchLogs.LogGroup != "" && (falcopayload.Priority >= types.Priority(config.AWS.CloudWatchLogs.MinimumPriority) || falcopayload.Rule == testRule) {
		go awsClient.SendCloudWatchLog(falcopayload)
	}

	if config.AWS.S3.Bucket != "" && (falcopayload.Priority >= types.Priority(config.AWS.S3.MinimumPriority) || falcopayload.Rule == testRule) {
		go awsClient.UploadS3(falcopayload)
	}

	if (config.AWS.SecurityLake.Bucket != "" && config.AWS.SecurityLake.Region != "" && config.AWS.SecurityLake.AccountID != "" && config.AWS.SecurityLake.Prefix != "") && (falcopayload.Priority >= types.Priority(config.AWS.SecurityLake.MinimumPriority) || falcopayload.Rule == testRule) {
		go awsClient.EnqueueSecurityLake(falcopayload)
	}

	if config.AWS.Kinesis.StreamName != "" && (falcopayload.Priority >= types.Priority(config.AWS.Kinesis.MinimumPriority) || falcopayload.Rule == testRule) {
		go awsClient.PutRecord(falcopayload)
	}

	if config.SMTP.HostPort != "" && (falcopayload.Priority >= types.Priority(config.SMTP.MinimumPriority) || falcopayload.Rule == testRule) {
		go smtpClient.SendMail(falcopayload)
	}

	if config.Opsgenie.APIKey != "" && (falcopayload.Priority >= types.Priority(config.Opsgenie.MinimumPriority) || falcopayload.Rule == testRule) {
		go opsgenieClient.OpsgeniePost(falcopayload)
	}

	if config.Webhook.Address != "" && (falcopayload.Priority >= types.Priority(config.Webhook.MinimumPriority) || falcopayload.Rule == testRule) {
		go webhookClient.WebhookPost(falcopayload)
	}

	if config.NodeRed.Address != "" && (falcopayload.Priority >= types.Priority(config.NodeRed.MinimumPriority) || falcopayload.Rule == testRule) {
		go noderedClient.NodeRedPost(falcopayload)
	}

	if config.CloudEvents.Address != "" && (falcopayload.Priority >= types.Priority(config.CloudEvents.MinimumPriority) || falcopayload.Rule == testRule) {
		go cloudeventsClient.CloudEventsSend(falcopayload)
	}

	if config.Azure.EventHub.Name != "" && (falcopayload.Priority >= types.Priority(config.Azure.EventHub.MinimumPriority) || falcopayload.Rule == testRule) {
		go azureClient.EventHubPost(falcopayload)
	}

	if config.GCP.PubSub.ProjectID != "" && config.GCP.PubSub.Topic != "" && (falcopayload.Priority >= types.Priority(config.GCP.PubSub.MinimumPriority) || falcopayload.Rule == testRule) {
		go gcpClient.GCPPublishTopic(falcopayload)
	}

	if config.GCP.CloudFunctions.Name != "" && (falcopayload.Priority >= types.Priority(config.GCP.CloudFunctions.MinimumPriority) || falcopayload.Rule == testRule) {
		go gcpClient.GCPCallCloudFunction(falcopayload)
	}

	if config.GCP.CloudRun.Endpoint != "" && (falcopayload.Priority >= types.Priority(config.GCP.CloudRun.MinimumPriority) || falcopayload.Rule == testRule) {
		go gcpCloudRunClient.CloudRunFunctionPost(falcopayload)
	}

	if config.GCP.Storage.Bucket != "" && (falcopayload.Priority >= types.Priority(config.GCP.Storage.MinimumPriority) || falcopayload.Rule == testRule) {
		go gcpClient.UploadGCS(falcopayload)
	}

	if config.Googlechat.WebhookURL != "" && (falcopayload.Priority >= types.Priority(config.Googlechat.MinimumPriority) || falcopayload.Rule == testRule) {
		go googleChatClient.GooglechatPost(falcopayload)
	}

	if config.Kafka.HostPort != "" && (falcopayload.Priority >= types.Priority(config.Kafka.MinimumPriority) || falcopayload.Rule == testRule) {
		go kafkaClient.KafkaProduce(falcopayload)
	}

	if config.KafkaRest.Address != "" && (falcopayload.Priority >= types.Priority(config.KafkaRest.MinimumPriority) || falcopayload.Rule == testRule) {
		go kafkaRestClient.KafkaRestPost(falcopayload)
	}

	if config.Pagerduty.RoutingKey != "" && (falcopayload.Priority >= types.Priority(config.Pagerduty.MinimumPriority) || falcopayload.Rule == testRule) {
		go pagerdutyClient.PagerdutyPost(falcopayload)
	}

	if config.Kubeless.Namespace != "" && config.Kubeless.Function != "" && (falcopayload.Priority >= types.Priority(config.Kubeless.MinimumPriority) || falcopayload.Rule == testRule) {
		go kubelessClient.KubelessCall(falcopayload)
	}

	if config.Openfaas.FunctionName != "" && (falcopayload.Priority >= types.Priority(config.Openfaas.MinimumPriority) || falcopayload.Rule == testRule) {
		go openfaasClient.OpenfaasCall(falcopayload)
	}

	if config.Tekton.EventListener != "" && (falcopayload.Priority >= types.Priority(config.Tekton.MinimumPriority) || falcopayload.Rule == testRule) {
		go tektonClient.TektonPost(falcopayload)
	}

	if config.Rabbitmq.URL != "" && config.Rabbitmq.Queue != "" && (falcopayload.Priority >= types.Priority(config.Openfaas.MinimumPriority) || falcopayload.Rule == testRule) {
		go rabbitmqClient.Publish(falcopayload)
	}

	if config.Wavefront.EndpointHost != "" && config.Wavefront.EndpointType != "" && (falcopayload.Priority >= types.Priority(config.Wavefront.MinimumPriority) || falcopayload.Rule == testRule) {
		go wavefrontClient.WavefrontPost(falcopayload)
	}

	if config.Grafana.HostPort != "" && (falcopayload.Priority >= types.Priority(config.Grafana.MinimumPriority) || falcopayload.Rule == testRule) {
		go grafanaClient.GrafanaPost(falcopayload)
	}

	if config.GrafanaOnCall.WebhookURL != "" && (falcopayload.Priority >= types.Priority(config.GrafanaOnCall.MinimumPriority) || falcopayload.Rule == testRule) {
		go grafanaOnCallClient.GrafanaOnCallPost(falcopayload)
	}

	if config.WebUI.URL != "" {
		go webUIClient.WebUIPost(falcopayload)
	}

	if config.Fission.Function != "" && (falcopayload.Priority >= types.Priority(config.Fission.MinimumPriority) || falcopayload.Rule == testRule) {
		go fissionClient.FissionCall(falcopayload)
	}
	if config.PolicyReport.Enabled && (falcopayload.Priority >= types.Priority(config.PolicyReport.MinimumPriority)) {
		go policyReportClient.UpdateOrCreatePolicyReport(falcopayload)
	}

	if config.Yandex.S3.Bucket != "" && (falcopayload.Priority >= types.Priority(config.Yandex.S3.MinimumPriority) || falcopayload.Rule == testRule) {
		go yandexClient.UploadYandexS3(falcopayload)
	}

	if config.Yandex.DataStreams.StreamName != "" && (falcopayload.Priority >= types.Priority(config.Yandex.DataStreams.MinimumPriority) || falcopayload.Rule == testRule) {
		go yandexClient.UploadYandexDataStreams(falcopayload)
	}

	if config.Syslog.Host != "" && (falcopayload.Priority >= types.Priority(config.Syslog.MinimumPriority) || falcopayload.Rule == testRule) {
		go syslogClient.SyslogPost(falcopayload)
	}

	if config.MQTT.Broker != "" && (falcopayload.Priority >= types.Priority(config.MQTT.MinimumPriority) || falcopayload.Rule == testRule) {
		go mqttClient.MQTTPublish(falcopayload)
	}

	if config.Zincsearch.HostPort != "" && (falcopayload.Priority >= types.Priority(config.Zincsearch.MinimumPriority) || falcopayload.Rule == testRule) {
		go zincsearchClient.ZincsearchPost(falcopayload)
	}

	if config.Gotify.HostPort != "" && (falcopayload.Priority >= types.Priority(config.Gotify.MinimumPriority) || falcopayload.Rule == testRule) {
		go gotifyClient.GotifyPost(falcopayload)
	}

	if config.Spyderbat.OrgUID != "" && (falcopayload.Priority >= types.Priority(config.Spyderbat.MinimumPriority) || falcopayload.Rule == testRule) {
		go spyderbatClient.SpyderbatPost(falcopayload)
	}

	if config.TimescaleDB.Host != "" && (falcopayload.Priority >= types.Priority(config.TimescaleDB.MinimumPriority) || falcopayload.Rule == testRule) {
		go timescaleDBClient.TimescaleDBPost(falcopayload)
	}

	if config.Redis.Address != "" && (falcopayload.Priority >= types.Priority(config.Redis.MinimumPriority) || falcopayload.Rule == testRule) {
		go redisClient.RedisPost(falcopayload)
	}

	if config.Telegram.ChatID != "" && config.Telegram.Token != "" && (falcopayload.Priority >= types.Priority(config.Telegram.MinimumPriority) || falcopayload.Rule == testRule) {
		go telegramClient.TelegramPost(falcopayload)
	}

	if config.N8N.Address != "" && (falcopayload.Priority >= types.Priority(config.N8N.MinimumPriority) || falcopayload.Rule == testRule) {
		go n8nClient.N8NPost(falcopayload)
	}

	if config.OpenObserve.HostPort != "" && (falcopayload.Priority >= types.Priority(config.OpenObserve.MinimumPriority) || falcopayload.Rule == testRule) {
		go openObserveClient.OpenObservePost(falcopayload)
	}

	if config.Dynatrace.APIToken != "" && config.Dynatrace.APIUrl != "" && (falcopayload.Priority >= types.Priority(config.Dynatrace.MinimumPriority) || falcopayload.Rule == testRule) {
		go dynatraceClient.DynatracePost(falcopayload)
	}

	if config.OTLP.Traces.Endpoint != "" && (falcopayload.Priority >= types.Priority(config.OTLP.Traces.MinimumPriority)) && (falcopayload.Source == "syscall" || falcopayload.Source == "syscalls") {
		go otlpClient.OTLPTracesPost(falcopayload)
	}
}
