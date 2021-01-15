package main

import (
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/falcosecurity/falcosidekick/types"
)

const TestRule string = "Test rule"

// mainHandler is Falco Sidekick main handler (default).
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
	if err != nil || len(falcopayload.Output) == 0 {
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
	w.Write([]byte("pong\n"))
}

// healthHandler is a simple handler to test if daemon is UP.
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	w.Write([]byte("{\"status\": \"ok\"}"))
}

// testHandler sends a test event to all enabled outputs.
func testHandler(w http.ResponseWriter, r *http.Request) {
	r.Body = ioutil.NopCloser(bytes.NewReader([]byte(`{"output":"This is a test from falcosidekick","priority":"Debug","rule":"Test rule", "time":"` + time.Now().UTC().Format(time.RFC3339) + `","outputfields": {"proc.name":"falcosidekick","user.name":"falcosidekick"}}`)))
	mainHandler(w, r)
}

func newFalcoPayload(payload io.Reader) (types.FalcoPayload, error) {
	var falcopayload types.FalcoPayload

	err := json.NewDecoder(payload).Decode(&falcopayload)
	if err != nil {
		return types.FalcoPayload{}, err
	}

	// falcopayload.OutputFields = make(map[string]interface{})
	if len(config.Customfields) > 0 {
		if falcopayload.OutputFields == nil {
			falcopayload.OutputFields = make(map[string]interface{})
		}
		for key, value := range config.Customfields {
			falcopayload.OutputFields[key] = value
		}
	}

	var kn, kp string
	for i, j := range falcopayload.OutputFields {
		if i == "k8s_ns_name" {
			kn = j.(string)
		}
		if i == "k8s_pod_name" {
			kp = j.(string)
		}
	}

	nullClient.CountMetric("falco.accepted", 1, []string{"priority:" + falcopayload.Priority.String()})
	stats.Falco.Add(falcopayload.Priority.String(), 1)
	promStats.Falco.With(map[string]string{"rule": falcopayload.Rule, "priority": falcopayload.Priority.String(), "k8s_ns_name": kn, "k8s_pod_name": kp}).Inc()

	if config.Debug == true {
		body, _ := json.Marshal(falcopayload)
		log.Printf("[DEBUG] : Falco's payload : %v", string(body))
	}

	return falcopayload, nil
}

func forwardEvent(falcopayload types.FalcoPayload) {
	if config.Slack.WebhookURL != "" && (falcopayload.Priority >= types.Priority(config.Slack.MinimumPriority) || falcopayload.Rule == TestRule) {
		go slackClient.SlackPost(falcopayload)
	}

	if config.Rocketchat.WebhookURL != "" && (falcopayload.Priority >= types.Priority(config.Rocketchat.MinimumPriority) || falcopayload.Rule == TestRule) {
		go rocketchatClient.RocketchatPost(falcopayload)
	}

	if config.Mattermost.WebhookURL != "" && (falcopayload.Priority >= types.Priority(config.Mattermost.MinimumPriority) || falcopayload.Rule == TestRule) {
		go mattermostClient.MattermostPost(falcopayload)
	}

	if config.Teams.WebhookURL != "" && (falcopayload.Priority >= types.Priority(config.Teams.MinimumPriority) || falcopayload.Rule == TestRule) {
		go teamsClient.TeamsPost(falcopayload)
	}

	if config.Datadog.APIKey != "" && (falcopayload.Priority >= types.Priority(config.Datadog.MinimumPriority) || falcopayload.Rule == TestRule) {
		go datadogClient.DatadogPost(falcopayload)
	}

	if config.Discord.WebhookURL != "" && (falcopayload.Priority >= types.Priority(config.Discord.MinimumPriority) || falcopayload.Rule == TestRule) {
		go discordClient.DiscordPost(falcopayload)
	}

	if config.Alertmanager.HostPort != "" && (falcopayload.Priority >= types.Priority(config.Alertmanager.MinimumPriority) || falcopayload.Rule == TestRule) {
		go alertmanagerClient.AlertmanagerPost(falcopayload)
	}

	if config.Elasticsearch.HostPort != "" && (falcopayload.Priority >= types.Priority(config.Elasticsearch.MinimumPriority) || falcopayload.Rule == TestRule) {
		go elasticsearchClient.ElasticsearchPost(falcopayload)
	}

	if config.Influxdb.HostPort != "" && (falcopayload.Priority >= types.Priority(config.Influxdb.MinimumPriority) || falcopayload.Rule == TestRule) {
		go influxdbClient.InfluxdbPost(falcopayload)
	}

	if config.Loki.HostPort != "" && (falcopayload.Priority >= types.Priority(config.Loki.MinimumPriority) || falcopayload.Rule == TestRule) {
		go lokiClient.LokiPost(falcopayload)
	}

	if config.Nats.HostPort != "" && (falcopayload.Priority >= types.Priority(config.Nats.MinimumPriority) || falcopayload.Rule == TestRule) {
		go natsClient.NatsPublish(falcopayload)
	}

	if config.Stan.HostPort != "" && config.Stan.ClusterID != "" && config.Stan.ClientID != "" && (falcopayload.Priority >= types.Priority(config.Stan.MinimumPriority) || falcopayload.Rule == TestRule) {
		go stanClient.StanPublish(falcopayload)
	}

	if config.AWS.Lambda.FunctionName != "" && (falcopayload.Priority >= types.Priority(config.AWS.Lambda.MinimumPriority) || falcopayload.Rule == TestRule) {
		go awsClient.InvokeLambda(falcopayload)
	}

	if config.AWS.SQS.URL != "" && (falcopayload.Priority >= types.Priority(config.AWS.SQS.MinimumPriority) || falcopayload.Rule == TestRule) {
		go awsClient.SendMessage(falcopayload)
	}

	if config.AWS.SNS.TopicArn != "" && (falcopayload.Priority >= types.Priority(config.AWS.SNS.MinimumPriority) || falcopayload.Rule == TestRule) {
		go awsClient.PublishTopic(falcopayload)
	}

	if config.AWS.CloudWatchLogs.LogGroup != "" && (falcopayload.Priority >= types.Priority(config.AWS.CloudWatchLogs.MinimumPriority) || falcopayload.Rule == TestRule) {
		go awsClient.SendCloudWatchLog(falcopayload)
	}

	if config.SMTP.HostPort != "" && (falcopayload.Priority >= types.Priority(config.SMTP.MinimumPriority) || falcopayload.Rule == TestRule) {
		go smtpClient.SendMail(falcopayload)
	}

	if config.Opsgenie.APIKey != "" && (falcopayload.Priority >= types.Priority(config.Opsgenie.MinimumPriority) || falcopayload.Rule == TestRule) {
		go opsgenieClient.OpsgeniePost(falcopayload)
	}

	if config.Webhook.Address != "" && (falcopayload.Priority >= types.Priority(config.Webhook.MinimumPriority) || falcopayload.Rule == TestRule) {
		go webhookClient.WebhookPost(falcopayload)
	}

	if config.CloudEvents.Address != "" && (falcopayload.Priority >= types.Priority(config.CloudEvents.MinimumPriority) || falcopayload.Rule == TestRule) {
		go cloudeventsClient.CloudEventsSend(falcopayload)
	}

	if config.Azure.EventHub.Name != "" && (falcopayload.Priority >= types.Priority(config.Azure.EventHub.MinimumPriority) || falcopayload.Rule == TestRule) {
		go azureClient.EventHubPost(falcopayload)
	}

	if config.GCP.PubSub.ProjectID != "" && config.GCP.PubSub.Topic != "" && (falcopayload.Priority >= types.Priority(config.GCP.PubSub.MinimumPriority) || falcopayload.Rule == TestRule) {
		go gcpClient.GCPPublishTopic(falcopayload)
	}

	if config.Googlechat.WebhookURL != "" && (falcopayload.Priority >= types.Priority(config.Googlechat.MinimumPriority) || falcopayload.Rule == TestRule) {
		go googleChatClient.GooglechatPost(falcopayload)
	}

	if config.Kafka.HostPort != "" && (falcopayload.Priority >= types.Priority(config.Kafka.MinimumPriority) || falcopayload.Rule == TestRule) {
		go kafkaClient.KafkaProduce(falcopayload)
	}

	if config.Pagerduty.APIKey != "" && config.Pagerduty.Service != "" && (falcopayload.Priority >= types.Priority(config.Pagerduty.MinimumPriority) || falcopayload.Rule == TestRule) {
		go pagerdutyClient.PagerdutyCreateIncident(falcopayload)
	}

	if config.Kubeless.Namespace != "" && config.Kubeless.Function != "" && (falcopayload.Priority >= types.Priority(config.Kubeless.MinimumPriority) || falcopayload.Rule == TestRule) {
		go kubelessClient.KubelessCall(falcopayload)
	}
}
