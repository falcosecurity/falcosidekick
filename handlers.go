package main

import (
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/falcosecurity/falcosidekick/types"
)

const TestRule string = "Test rule"

func getPriorityMap() map[string]int {
	return map[string]int{
		"emergency":     8,
		"alert":         7,
		"critical":      6,
		"error":         5,
		"warning":       4,
		"notice":        3,
		"informational": 2,
		"debug":         1,
		"":              0,
	}
}

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
	p := "unknown"
	priority := strings.ToLower(falcopayload.Priority)

	switch priority {
	case "emergency", "alert", "critical", "error", "warning", "notice", "informational", "debug":
		p = priority
	}

	for i, j := range falcopayload.OutputFields {
		if i == "k8s_ns_name" {
			kn = j.(string)
		}
		if i == "k8s_pod_name" {
			kp = j.(string)
		}
	}

	nullClient.CountMetric("falco.accepted", 1, []string{"priority:" + p})
	stats.Falco.Add(p, 1)
	promStats.Falco.With(map[string]string{"rule": falcopayload.Rule, "priority": p, "k8s_ns_name": kn, "k8s_pod_name": kp}).Inc()

	if config.Debug == true {
		body, _ := json.Marshal(falcopayload)
		log.Printf("[DEBUG] : Falco's payload : %v", string(body))
	}

	return falcopayload, nil
}

func forwardEvent(falcopayload types.FalcoPayload) {
	if config.Slack.WebhookURL != "" && (priorityMap[strings.ToLower(falcopayload.Priority)] >= priorityMap[strings.ToLower(config.Slack.MinimumPriority)] || falcopayload.Rule == TestRule) {
		go slackClient.SlackPost(falcopayload)
	}

	if config.Rocketchat.WebhookURL != "" && (priorityMap[strings.ToLower(falcopayload.Priority)] >= priorityMap[strings.ToLower(config.Rocketchat.MinimumPriority)] || falcopayload.Rule == TestRule) {
		go rocketchatClient.RocketchatPost(falcopayload)
	}

	if config.Mattermost.WebhookURL != "" && (priorityMap[strings.ToLower(falcopayload.Priority)] >= priorityMap[strings.ToLower(config.Mattermost.MinimumPriority)] || falcopayload.Rule == TestRule) {
		go mattermostClient.MattermostPost(falcopayload)
	}

	if config.Teams.WebhookURL != "" && (priorityMap[strings.ToLower(falcopayload.Priority)] >= priorityMap[strings.ToLower(config.Teams.MinimumPriority)] || falcopayload.Rule == TestRule) {
		go teamsClient.TeamsPost(falcopayload)
	}

	if config.Datadog.APIKey != "" && (priorityMap[strings.ToLower(falcopayload.Priority)] >= priorityMap[strings.ToLower(config.Datadog.MinimumPriority)] || falcopayload.Rule == TestRule) {
		go datadogClient.DatadogPost(falcopayload)
	}

	if config.Discord.WebhookURL != "" && (priorityMap[strings.ToLower(falcopayload.Priority)] >= priorityMap[strings.ToLower(config.Discord.MinimumPriority)] || falcopayload.Rule == TestRule) {
		go discordClient.DiscordPost(falcopayload)
	}

	if config.Alertmanager.HostPort != "" && (priorityMap[strings.ToLower(falcopayload.Priority)] >= priorityMap[strings.ToLower(config.Alertmanager.MinimumPriority)] || falcopayload.Rule == TestRule) {
		go alertmanagerClient.AlertmanagerPost(falcopayload)
	}

	if config.Elasticsearch.HostPort != "" && (priorityMap[strings.ToLower(falcopayload.Priority)] >= priorityMap[strings.ToLower(config.Elasticsearch.MinimumPriority)] || falcopayload.Rule == TestRule) {
		go elasticsearchClient.ElasticsearchPost(falcopayload)
	}

	if config.Influxdb.HostPort != "" && (priorityMap[strings.ToLower(falcopayload.Priority)] >= priorityMap[strings.ToLower(config.Influxdb.MinimumPriority)] || falcopayload.Rule == TestRule) {
		go influxdbClient.InfluxdbPost(falcopayload)
	}

	if config.Loki.HostPort != "" && (priorityMap[strings.ToLower(falcopayload.Priority)] >= priorityMap[strings.ToLower(config.Loki.MinimumPriority)] || falcopayload.Rule == TestRule) {
		go lokiClient.LokiPost(falcopayload)
	}

	if config.Nats.HostPort != "" && (priorityMap[strings.ToLower(falcopayload.Priority)] >= priorityMap[strings.ToLower(config.Nats.MinimumPriority)] || falcopayload.Rule == TestRule) {
		go natsClient.NatsPublish(falcopayload)
	}

	if config.Stan.HostPort != "" && config.Stan.ClusterID != "" && config.Stan.ClientID != "" && (priorityMap[strings.ToLower(falcopayload.Priority)] >= priorityMap[strings.ToLower(config.Stan.MinimumPriority)] || falcopayload.Rule == TestRule) {
		go stanClient.StanPublish(falcopayload)
	}

	if config.AWS.Lambda.FunctionName != "" && (priorityMap[strings.ToLower(falcopayload.Priority)] >= priorityMap[strings.ToLower(config.AWS.Lambda.MinimumPriority)] || falcopayload.Rule == TestRule) {
		go awsClient.InvokeLambda(falcopayload)
	}

	if config.AWS.SQS.URL != "" && (priorityMap[strings.ToLower(falcopayload.Priority)] >= priorityMap[strings.ToLower(config.AWS.SQS.MinimumPriority)] || falcopayload.Rule == TestRule) {
		go awsClient.SendMessage(falcopayload)
	}

	if config.AWS.SNS.TopicArn != "" && (priorityMap[strings.ToLower(falcopayload.Priority)] >= priorityMap[strings.ToLower(config.AWS.SNS.MinimumPriority)] || falcopayload.Rule == TestRule) {
		go awsClient.PublishTopic(falcopayload)
	}

	if config.AWS.CloudWatchLogs.LogGroup != "" && (priorityMap[strings.ToLower(falcopayload.Priority)] >= priorityMap[strings.ToLower(config.AWS.CloudWatchLogs.MinimumPriority)] || falcopayload.Rule == TestRule) {
		go awsClient.SendCloudWatchLog(falcopayload)
	}

	if config.SMTP.HostPort != "" && (priorityMap[strings.ToLower(falcopayload.Priority)] >= priorityMap[strings.ToLower(config.SMTP.MinimumPriority)] || falcopayload.Rule == TestRule) {
		go smtpClient.SendMail(falcopayload)
	}

	if config.Opsgenie.APIKey != "" && (priorityMap[strings.ToLower(falcopayload.Priority)] >= priorityMap[strings.ToLower(config.Opsgenie.MinimumPriority)] || falcopayload.Rule == TestRule) {
		go opsgenieClient.OpsgeniePost(falcopayload)
	}

	if config.Webhook.Address != "" && (priorityMap[strings.ToLower(falcopayload.Priority)] >= priorityMap[strings.ToLower(config.Webhook.MinimumPriority)] || falcopayload.Rule == TestRule) {
		go webhookClient.WebhookPost(falcopayload)
	}

	if config.Azure.EventHub.Name != "" && (priorityMap[strings.ToLower(falcopayload.Priority)] >= priorityMap[strings.ToLower(config.Azure.EventHub.MinimumPriority)] || falcopayload.Rule == TestRule) {
		go azureClient.EventHubPost(falcopayload)
	}

	if config.GCP.PubSub.ProjectID != "" && config.GCP.PubSub.Topic != "" && (priorityMap[strings.ToLower(falcopayload.Priority)] >= priorityMap[strings.ToLower(config.GCP.PubSub.MinimumPriority)] || falcopayload.Rule == TestRule) {
		go gcpClient.GCPPublishTopic(falcopayload)
	}

	if config.Googlechat.WebhookURL != "" && (priorityMap[strings.ToLower(falcopayload.Priority)] >= priorityMap[strings.ToLower(config.Googlechat.MinimumPriority)] || falcopayload.Rule == TestRule) {
		go googleChatClient.GooglechatPost(falcopayload)
	}

	if config.Kafka.HostPort != "" && (priorityMap[strings.ToLower(falcopayload.Priority)] >= priorityMap[strings.ToLower(config.Kafka.MinimumPriority)] || falcopayload.Rule == TestRule) {
		go kafkaClient.KafkaProduce(falcopayload)
	}

	if config.Pagerduty.APIKey != "" && config.Pagerduty.Service != "" && (priorityMap[strings.ToLower(falcopayload.Priority)] >= priorityMap[strings.ToLower(config.Pagerduty.MinimumPriority)] || falcopayload.Rule == TestRule) {
		go pagerdutyClient.PagerdutyCreateIncident(falcopayload)
	}
}
