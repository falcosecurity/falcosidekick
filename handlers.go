// SPDX-License-Identifier: MIT OR Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/falcosecurity/falcosidekick/internal/pkg/utils"
	"github.com/falcosecurity/falcosidekick/types"
)

const (
	testRule string = "Test rule"
	syscalls string = "syscalls"
	syscall  string = "syscall"
)

// mainHandler is Falcosidekick main handler (default).
func mainHandler(w http.ResponseWriter, r *http.Request) {
	stats.Requests.Add("total", 1)
	nullClient.CountMetric("total", 1, []string{})

	if r.Body == nil {
		http.Error(w, "Please send a valid request body", http.StatusBadRequest)
		stats.Requests.Add("rejected", 1)
		promStats.Inputs.With(map[string]string{"source": "requests", "status": "rejected"}).Inc()
		otlpMetrics.Inputs.With(attribute.String("source", "requests"),
			attribute.String("status", "rejected")).Inc()
		nullClient.CountMetric("inputs.requests.rejected", 1, []string{"error:nobody"})

		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Please send with post http method", http.StatusBadRequest)
		stats.Requests.Add("rejected", 1)
		promStats.Inputs.With(map[string]string{"source": "requests", "status": "rejected"}).Inc()
		otlpMetrics.Inputs.With(attribute.String("source", "requests"),
			attribute.String("status", "rejected")).Inc()
		nullClient.CountMetric("inputs.requests.rejected", 1, []string{"error:nobody"})

		return
	}

	falcopayload, err := newFalcoPayload(r.Body)
	if err != nil || !falcopayload.Check() {
		http.Error(w, "Please send a valid request body", http.StatusBadRequest)
		stats.Requests.Add("rejected", 1)
		promStats.Inputs.With(map[string]string{"source": "requests", "status": "rejected"}).Inc()
		otlpMetrics.Inputs.With(attribute.String("source", "requests"),
			attribute.String("status", "rejected")).Inc()
		nullClient.CountMetric("inputs.requests.rejected", 1, []string{"error:invalidjson"})

		return
	}

	nullClient.CountMetric("inputs.requests.accepted", 1, []string{})
	stats.Requests.Add("accepted", 1)
	promStats.Inputs.With(map[string]string{"source": "requests", "status": "accepted"}).Inc()
	otlpMetrics.Inputs.With(attribute.String("source", "requests"),
		attribute.String("status", "accepted")).Inc()
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
	r.Body = io.NopCloser(bytes.NewReader([]byte(`{"output":"This is a test from falcosidekick","source":"debug","priority":"Debug","hostname":"falcosidekick", "rule":"Test rule","time":"` + time.Now().UTC().Format(time.RFC3339) + `","output_fields":{"proc.name":"falcosidekick","user.name":"falcosidekick"},"tags":["test","example"]}`)))
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

	falcopayload.Tags = append(falcopayload.Tags, config.Customtags...)

	if falcopayload.Rule == "Test rule" {
		falcopayload.Source = "internal"
	}

	if falcopayload.Source == "" {
		falcopayload.Source = syscalls
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
				utils.Log(utils.ErrorLvl, "", fmt.Sprintf("Parsing error for templated field '%v': %v", key, err))
				continue
			}
			v := new(bytes.Buffer)
			if err := tmpl.Execute(v, falcopayload.OutputFields); err != nil {
				utils.Log(utils.ErrorLvl, "", fmt.Sprintf("Parsing error for templated field '%v': %v", key, err))
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
	promLabels := map[string]string{
		"rule":         falcopayload.Rule,
		"priority_raw": strings.ToLower(falcopayload.Priority.String()),
		"priority":     strconv.Itoa(int(falcopayload.Priority)),
		"source":       falcopayload.Source,
		"k8s_ns_name":  kn,
		"k8s_pod_name": kp,
	}
	if falcopayload.Hostname != "" {
		promLabels["hostname"] = falcopayload.Hostname
	} else {
		promLabels["hostname"] = "unknown"
	}

	for key, value := range config.Customfields {
		sanitizedKey := strings.ReplaceAll(key, ".", "_")
		if regPromLabels.MatchString(sanitizedKey) {
			promLabels[sanitizedKey] = value
		}
	}
	for key := range config.Templatedfields {
		sanitizedKey := strings.ReplaceAll(key, ".", "_")
		if regPromLabels.MatchString(sanitizedKey) {
			promLabels[sanitizedKey] = fmt.Sprintf("%v", falcopayload.OutputFields[key])
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

	// Falco OTLP metric
	hostname := falcopayload.Hostname
	if hostname == "" {
		hostname = "unknown"
	}
	attrs := []attribute.KeyValue{
		attribute.String("source", falcopayload.Source),
		attribute.String("priority", falcopayload.Priority.String()),
		attribute.String("rule", falcopayload.Rule),
		attribute.String("hostname", hostname),
		attribute.StringSlice("tags", falcopayload.Tags),
	}

	for key, value := range config.Customfields {
		sanitizedKey := strings.ReplaceAll(key, ".", "_")
		if regOTLPMetricsAttributes.MatchString(sanitizedKey) {
			attrs = append(attrs, attribute.String(sanitizedKey, value))
		}
	}
	for _, attr := range config.OTLP.Metrics.ExtraAttributesList {
		attrName := strings.ReplaceAll(attr, ".", "_")
		attrValue := ""
		for key, val := range falcopayload.OutputFields {
			if key != attr {
				continue
			}
			if keyName := strings.ReplaceAll(key, ".", "_"); !regOTLPMetricsAttributes.MatchString(keyName) {
				continue
			}
			// Notice: Don't remove the _ for the second return value, otherwise will panic if it can convert the value
			// to string
			attrValue, _ = val.(string)
			break
		}
		attrs = append(attrs, attribute.String(attrName, attrValue))
	}
	otlpMetrics.Falco.With(attrs...).Inc()

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
			n = strings.ReplaceAll(n, "<tags>", strings.Join(falcopayload.Tags, ","))
			n = strings.TrimSuffix(n, " ")
			n = strings.TrimSuffix(n, "( )")
			n = strings.TrimSuffix(n, "()")
			n = strings.TrimSuffix(n, " ")
			falcopayload.Output = n
		}
	}

	if len(falcopayload.String()) > 4096 {
		for i, j := range falcopayload.OutputFields {
			switch l := j.(type) {
			case string:
				if len(l) > 512 {
					k := j.(string)[:507] + "[...]"
					falcopayload.Output = strings.ReplaceAll(falcopayload.Output, j.(string), k)
					falcopayload.OutputFields[i] = k
				}
			}
		}
	}

	if config.Debug {
		utils.Log(utils.DebugLvl, "", fmt.Sprintf("Falco's payload : %v", falcopayload.String()))
	}

	return falcopayload, nil
}

// safeGo runs fn in its own goroutine, recovering from any panic so that a single
// malformed event or misbehaving output cannot bring down the whole process.
func safeGo(fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				utils.Log(utils.ErrorLvl, "", fmt.Sprintf("recovered from panic while forwarding event: %v", r))
			}
		}()
		fn()
	}()
}

func forwardEvent(falcopayload types.FalcoPayload) {
	var dispatches []func(types.FalcoPayload)

	if config.Slack.WebhookURL != "" && (falcopayload.Priority >= types.Priority(config.Slack.MinimumPriority) || falcopayload.Rule == testRule) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { slackClient.SlackPost(p) })
	}

	if config.Cliq.WebhookURL != "" && (falcopayload.Priority >= types.Priority(config.Cliq.MinimumPriority) || falcopayload.Rule == testRule) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { cliqClient.CliqPost(p) })
	}

	if config.Rocketchat.WebhookURL != "" && (falcopayload.Priority >= types.Priority(config.Rocketchat.MinimumPriority) || falcopayload.Rule == testRule) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { rocketchatClient.RocketchatPost(p) })
	}

	if config.Mattermost.WebhookURL != "" && (falcopayload.Priority >= types.Priority(config.Mattermost.MinimumPriority) || falcopayload.Rule == testRule) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { mattermostClient.MattermostPost(p) })
	}

	if config.Teams.WebhookURL != "" && (falcopayload.Priority >= types.Priority(config.Teams.MinimumPriority) || falcopayload.Rule == testRule) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { teamsClient.TeamsPost(p) })
	}

	if config.Webex.WebhookURL != "" && (falcopayload.Priority >= types.Priority(config.Webex.MinimumPriority) || falcopayload.Rule == testRule) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { webexClient.WebexPost(p) })
	}

	if config.Datadog.APIKey != "" && (falcopayload.Priority >= types.Priority(config.Datadog.MinimumPriority) || falcopayload.Rule == testRule) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { datadogClient.DatadogPost(p) })
	}

	if config.DatadogLogs.APIKey != "" && (falcopayload.Priority >= types.Priority(config.DatadogLogs.MinimumPriority) || falcopayload.Rule == testRule) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { datadogLogsClient.DatadogLogsPost(p) })
	}

	if config.Discord.WebhookURL != "" && (falcopayload.Priority >= types.Priority(config.Discord.MinimumPriority) || falcopayload.Rule == testRule) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { discordClient.DiscordPost(p) })
	}

	if len(config.Alertmanager.HostPort) != 0 && (falcopayload.Priority >= types.Priority(config.Alertmanager.MinimumPriority) || falcopayload.Rule == testRule) {
		for _, i := range alertmanagerClients {
			i := i
			dispatches = append(dispatches, func(p types.FalcoPayload) { i.AlertmanagerPost(p) })
		}
	}

	if config.Elasticsearch.HostPort != "" && (falcopayload.Priority >= types.Priority(config.Elasticsearch.MinimumPriority) || falcopayload.Rule == testRule) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { elasticsearchClient.ElasticsearchPost(p) })
	}

	if config.Quickwit.HostPort != "" && (falcopayload.Priority >= types.Priority(config.Quickwit.MinimumPriority) || falcopayload.Rule == testRule) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { quickwitClient.QuickwitPost(p) })
	}

	if config.Influxdb.HostPort != "" && (falcopayload.Priority >= types.Priority(config.Influxdb.MinimumPriority) || falcopayload.Rule == testRule) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { influxdbClient.InfluxdbPost(p) })
	}

	if config.Loki.HostPort != "" && (falcopayload.Priority >= types.Priority(config.Loki.MinimumPriority) || falcopayload.Rule == testRule) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { lokiClient.LokiPost(p) })
	}

	if config.SumoLogic.ReceiverURL != "" && (falcopayload.Priority >= types.Priority(config.SumoLogic.MinimumPriority) || falcopayload.Rule == testRule) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { sumologicClient.SumoLogicPost(p) })
	}

	if config.Nats.HostPort != "" && (falcopayload.Priority >= types.Priority(config.Nats.MinimumPriority) || falcopayload.Rule == testRule) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { natsClient.NatsPublish(p) })
	}

	if config.Stan.HostPort != "" && config.Stan.ClusterID != "" && config.Stan.ClientID != "" && (falcopayload.Priority >= types.Priority(config.Stan.MinimumPriority) || falcopayload.Rule == testRule) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { stanClient.StanPublish(p) })
	}

	if config.AWS.Lambda.FunctionName != "" && (falcopayload.Priority >= types.Priority(config.AWS.Lambda.MinimumPriority) || falcopayload.Rule == testRule) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { awsClient.InvokeLambda(p) })
	}

	if config.AWS.SQS.URL != "" && (falcopayload.Priority >= types.Priority(config.AWS.SQS.MinimumPriority) || falcopayload.Rule == testRule) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { awsClient.SendMessage(p) })
	}

	if config.AWS.SNS.TopicArn != "" && (falcopayload.Priority >= types.Priority(config.AWS.SNS.MinimumPriority) || falcopayload.Rule == testRule) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { awsClient.PublishTopic(p) })
	}

	if config.AWS.CloudWatchLogs.LogGroup != "" && (falcopayload.Priority >= types.Priority(config.AWS.CloudWatchLogs.MinimumPriority) || falcopayload.Rule == testRule) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { awsClient.SendCloudWatchLog(p) })
	}

	if config.AWS.S3.Bucket != "" && (falcopayload.Priority >= types.Priority(config.AWS.S3.MinimumPriority) || falcopayload.Rule == testRule) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { awsClient.UploadS3(p) })
	}

	if (config.AWS.SecurityLake.Bucket != "" && config.AWS.SecurityLake.Region != "" && config.AWS.SecurityLake.AccountID != "" && config.AWS.SecurityLake.Prefix != "") && (falcopayload.Priority >= types.Priority(config.AWS.SecurityLake.MinimumPriority) || falcopayload.Rule == testRule) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { awsClient.EnqueueSecurityLake(p) })
	}

	if config.AWS.Kinesis.StreamName != "" && (falcopayload.Priority >= types.Priority(config.AWS.Kinesis.MinimumPriority) || falcopayload.Rule == testRule) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { awsClient.PutRecord(p) })
	}

	if config.SMTP.HostPort != "" && (falcopayload.Priority >= types.Priority(config.SMTP.MinimumPriority) || falcopayload.Rule == testRule) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { smtpClient.SendMail(p) })
	}

	if config.Opsgenie.APIKey != "" && (falcopayload.Priority >= types.Priority(config.Opsgenie.MinimumPriority) || falcopayload.Rule == testRule) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { opsgenieClient.OpsgeniePost(p) })
	}

	if config.Webhook.Address != "" && (falcopayload.Priority >= types.Priority(config.Webhook.MinimumPriority) || falcopayload.Rule == testRule) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { webhookClient.WebhookPost(p) })
	}

	if config.Splunk.Host != "" && (falcopayload.Priority >= types.Priority(config.Splunk.MinimumPriority) || falcopayload.Rule == testRule) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { splunkClient.Send(p) })
	}

	if config.NodeRed.Address != "" && (falcopayload.Priority >= types.Priority(config.NodeRed.MinimumPriority) || falcopayload.Rule == testRule) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { noderedClient.NodeRedPost(p) })
	}

	if config.CloudEvents.Address != "" && (falcopayload.Priority >= types.Priority(config.CloudEvents.MinimumPriority) || falcopayload.Rule == testRule) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { cloudeventsClient.CloudEventsSend(p) })
	}

	if config.Azure.EventHub.Name != "" && (falcopayload.Priority >= types.Priority(config.Azure.EventHub.MinimumPriority) || falcopayload.Rule == testRule) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { azureClient.EventHubPost(p) })
	}

	if config.GCP.PubSub.ProjectID != "" && config.GCP.PubSub.Topic != "" && (falcopayload.Priority >= types.Priority(config.GCP.PubSub.MinimumPriority) || falcopayload.Rule == testRule) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { gcpClient.GCPPublishTopic(p) })
	}

	if config.GCP.CloudFunctions.Name != "" && (falcopayload.Priority >= types.Priority(config.GCP.CloudFunctions.MinimumPriority) || falcopayload.Rule == testRule) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { gcpClient.GCPCallCloudFunction(p) })
	}

	if config.GCP.CloudRun.Endpoint != "" && (falcopayload.Priority >= types.Priority(config.GCP.CloudRun.MinimumPriority) || falcopayload.Rule == testRule) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { gcpCloudRunClient.CloudRunFunctionPost(p) })
	}

	if config.GCP.Storage.Bucket != "" && (falcopayload.Priority >= types.Priority(config.GCP.Storage.MinimumPriority) || falcopayload.Rule == testRule) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { gcpClient.UploadGCS(p) })
	}

	if config.GCP.Chronicle.Region != "" && config.GCP.Chronicle.ProjectID != "" && config.GCP.Chronicle.InstanceID != "" && gcpClient != nil && (falcopayload.Priority >= types.Priority(config.GCP.Chronicle.MinimumPriority) || falcopayload.Rule == testRule) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { gcpClient.GCPChronicleIngest(p) })
	}

	if config.Googlechat.WebhookURL != "" && (falcopayload.Priority >= types.Priority(config.Googlechat.MinimumPriority) || falcopayload.Rule == testRule) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { googleChatClient.GooglechatPost(p) })
	}

	if config.Kafka.HostPort != "" && (falcopayload.Priority >= types.Priority(config.Kafka.MinimumPriority) || falcopayload.Rule == testRule) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { kafkaClient.KafkaProduce(p) })
	}

	if config.KafkaRest.Address != "" && (falcopayload.Priority >= types.Priority(config.KafkaRest.MinimumPriority) || falcopayload.Rule == testRule) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { kafkaRestClient.KafkaRestPost(p) })
	}

	if config.Pagerduty.RoutingKey != "" && (falcopayload.Priority >= types.Priority(config.Pagerduty.MinimumPriority) || falcopayload.Rule == testRule) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { pagerdutyClient.PagerdutyPost(p) })
	}

	if config.Kubeless.Namespace != "" && config.Kubeless.Function != "" && (falcopayload.Priority >= types.Priority(config.Kubeless.MinimumPriority) || falcopayload.Rule == testRule) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { kubelessClient.KubelessCall(p) })
	}

	if config.Openfaas.FunctionName != "" && (falcopayload.Priority >= types.Priority(config.Openfaas.MinimumPriority) || falcopayload.Rule == testRule) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { openfaasClient.OpenfaasCall(p) })
	}

	if config.Tekton.EventListener != "" && (falcopayload.Priority >= types.Priority(config.Tekton.MinimumPriority) || falcopayload.Rule == testRule) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { tektonClient.TektonPost(p) })
	}

	if config.Rabbitmq.URL != "" && config.Rabbitmq.Queue != "" && (falcopayload.Priority >= types.Priority(config.Rabbitmq.MinimumPriority) || falcopayload.Rule == testRule) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { rabbitmqClient.Publish(p) })
	}

	if config.Wavefront.EndpointHost != "" && config.Wavefront.EndpointType != "" && (falcopayload.Priority >= types.Priority(config.Wavefront.MinimumPriority) || falcopayload.Rule == testRule) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { wavefrontClient.WavefrontPost(p) })
	}

	if config.Grafana.HostPort != "" && (falcopayload.Priority >= types.Priority(config.Grafana.MinimumPriority) || falcopayload.Rule == testRule) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { grafanaClient.GrafanaPost(p) })
	}

	if config.GrafanaOnCall.WebhookURL != "" && (falcopayload.Priority >= types.Priority(config.GrafanaOnCall.MinimumPriority) || falcopayload.Rule == testRule) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { grafanaOnCallClient.GrafanaOnCallPost(p) })
	}

	if config.WebUI.URL != "" {
		dispatches = append(dispatches, func(p types.FalcoPayload) { webUIClient.WebUIPost(p) })
	}

	if config.Fission.Function != "" && (falcopayload.Priority >= types.Priority(config.Fission.MinimumPriority) || falcopayload.Rule == testRule) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { fissionClient.FissionCall(p) })
	}

	if config.PolicyReport.Enabled && (falcopayload.Priority >= types.Priority(config.PolicyReport.MinimumPriority)) {
		if falcopayload.Source == syscalls || falcopayload.Source == syscall || falcopayload.Source == "k8saudit" {
			dispatches = append(dispatches, func(p types.FalcoPayload) { policyReportClient.UpdateOrCreatePolicyReport(p) })
		}
	}

	if config.Yandex.S3.Bucket != "" && (falcopayload.Priority >= types.Priority(config.Yandex.S3.MinimumPriority) || falcopayload.Rule == testRule) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { yandexClient.UploadYandexS3(p) })
	}

	if config.Yandex.DataStreams.StreamName != "" && (falcopayload.Priority >= types.Priority(config.Yandex.DataStreams.MinimumPriority) || falcopayload.Rule == testRule) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { yandexClient.UploadYandexDataStreams(p) })
	}

	if config.Syslog.Host != "" && (falcopayload.Priority >= types.Priority(config.Syslog.MinimumPriority) || falcopayload.Rule == testRule) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { syslogClient.SyslogPost(p) })
	}

	if config.MQTT.Broker != "" && (falcopayload.Priority >= types.Priority(config.MQTT.MinimumPriority) || falcopayload.Rule == testRule) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { mqttClient.MQTTPublish(p) })
	}

	if config.Zincsearch.HostPort != "" && (falcopayload.Priority >= types.Priority(config.Zincsearch.MinimumPriority) || falcopayload.Rule == testRule) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { zincsearchClient.ZincsearchPost(p) })
	}

	if config.Gotify.HostPort != "" && (falcopayload.Priority >= types.Priority(config.Gotify.MinimumPriority) || falcopayload.Rule == testRule) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { gotifyClient.GotifyPost(p) })
	}

	if config.Spyderbat.OrgUID != "" && (falcopayload.Priority >= types.Priority(config.Spyderbat.MinimumPriority) || falcopayload.Rule == testRule) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { spyderbatClient.SpyderbatPost(p) })
	}

	if config.TimescaleDB.Host != "" && (falcopayload.Priority >= types.Priority(config.TimescaleDB.MinimumPriority) || falcopayload.Rule == testRule) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { timescaleDBClient.TimescaleDBPost(p) })
	}

	if config.Redis.Address != "" && (falcopayload.Priority >= types.Priority(config.Redis.MinimumPriority) || falcopayload.Rule == testRule) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { redisClient.RedisPost(p) })
	}

	if config.Telegram.ChatID != "" && config.Telegram.Token != "" && (falcopayload.Priority >= types.Priority(config.Telegram.MinimumPriority) || falcopayload.Rule == testRule) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { telegramClient.TelegramPost(p) })
	}

	if config.N8N.Address != "" && (falcopayload.Priority >= types.Priority(config.N8N.MinimumPriority) || falcopayload.Rule == testRule) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { n8nClient.N8NPost(p) })
	}

	if config.OpenObserve.HostPort != "" && (falcopayload.Priority >= types.Priority(config.OpenObserve.MinimumPriority) || falcopayload.Rule == testRule) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { openObserveClient.OpenObservePost(p) })
	}

	if config.Dynatrace.APIToken != "" && config.Dynatrace.APIUrl != "" && (falcopayload.Priority >= types.Priority(config.Dynatrace.MinimumPriority) || falcopayload.Rule == testRule) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { dynatraceClient.DynatracePost(p) })
	}

	if config.OTLP.Traces.Endpoint != "" && (falcopayload.Priority >= types.Priority(config.OTLP.Traces.MinimumPriority)) && (falcopayload.Source == syscall || falcopayload.Source == syscalls) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { otlpTracesClient.OTLPTracesPost(p) })
	}

	if config.OTLP.Logs.Endpoint != "" && (falcopayload.Priority >= types.Priority(config.OTLP.Logs.MinimumPriority)) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { otlpLogsClient.OTLPLogsPost(p) })
	}

	if config.Talon.Address != "" && (falcopayload.Priority >= types.Priority(config.Talon.MinimumPriority) || falcopayload.Rule == testRule) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { talonClient.TalonPost(p) })
	}

	if config.Logstash.Address != "" && (falcopayload.Priority >= types.Priority(config.Logstash.MinimumPriority) || falcopayload.Rule == testRule) {
		dispatches = append(dispatches, func(p types.FalcoPayload) { logstashClient.LogstashPost(p) })
	}

	multipleOutputs := len(dispatches) > 1
	for _, fn := range dispatches {
		fn := fn
		if multipleOutputs {
			safeGo(func() { fn(falcopayload.DeepCopy()) })
		} else {
			safeGo(func() { fn(falcopayload) })
		}
	}
}
