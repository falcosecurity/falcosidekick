package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/falcosecurity/falcosidekick/types"
)

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
		http.Error(w, "Please send a valid request body", 400)
		stats.Requests.Add("rejected", 1)
		promStats.Inputs.With(map[string]string{"source": "requests", "status": "rejected"}).Inc()
		nullClient.CountMetric("inputs.requests.rejected", 1, []string{"error:nobody"})
		return
	}

	falcopayload, err := newFalcoPayload(r.Body)
	if err != nil || len(falcopayload.Output) == 0 {
		http.Error(w, "Please send a valid request body", 400)
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

// testHandler sends a test event to all enabled outputs.
func testHandler(w http.ResponseWriter, r *http.Request) {
	testEvent := `{"output":"This is a test from falcosidekick","priority":"Debug","rule":"Test rule", "time":"` + time.Now().UTC().Format(time.RFC3339) + `","outputfields": {"proc.name":"falcosidekick","user.name":"falcosidekick"}}`

	resp, err := http.Post("http://localhost:"+strconv.Itoa(config.ListenPort), "application/json", bytes.NewBuffer([]byte(testEvent)))
	if err != nil {
		log.Printf("[DEBUG] : Test Failed. Falcosidekick can't call itself\n")
	}
	defer resp.Body.Close()

	log.Printf("[DEBUG] : Test sent\n")
	if resp.StatusCode != http.StatusOK {
		log.Printf("[DEBUG] : Test KO (%v)\n", resp.Status)
	}
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
	if config.Slack.WebhookURL != "" && (priorityMap[strings.ToLower(falcopayload.Priority)] >= priorityMap[strings.ToLower(config.Slack.MinimumPriority)] || falcopayload.Rule == "Test rule") {
		go slackClient.SlackPost(falcopayload)
	}
	if config.Rocketchat.WebhookURL != "" && (priorityMap[strings.ToLower(falcopayload.Priority)] >= priorityMap[strings.ToLower(config.Rocketchat.MinimumPriority)] || falcopayload.Rule == "Test rule") {
		go rocketchatClient.RocketchatPost(falcopayload)
	}
	if config.Mattermost.WebhookURL != "" && (priorityMap[strings.ToLower(falcopayload.Priority)] >= priorityMap[strings.ToLower(config.Mattermost.MinimumPriority)] || falcopayload.Rule == "Test rule") {
		go mattermostClient.MattermostPost(falcopayload)
	}
	if config.Teams.WebhookURL != "" && (priorityMap[strings.ToLower(falcopayload.Priority)] >= priorityMap[strings.ToLower(config.Teams.MinimumPriority)] || falcopayload.Rule == "Test rule") {
		go teamsClient.TeamsPost(falcopayload)
	}
	if config.Datadog.APIKey != "" && (priorityMap[strings.ToLower(falcopayload.Priority)] >= priorityMap[strings.ToLower(config.Datadog.MinimumPriority)] || falcopayload.Rule == "Test rule") {
		go datadogClient.DatadogPost(falcopayload)
	}
	if config.Discord.WebhookURL != "" && (priorityMap[strings.ToLower(falcopayload.Priority)] >= priorityMap[strings.ToLower(config.Discord.MinimumPriority)] || falcopayload.Rule == "Test rule") {
		go discordClient.DiscordPost(falcopayload)
	}
	if config.Alertmanager.HostPort != "" && (priorityMap[strings.ToLower(falcopayload.Priority)] >= priorityMap[strings.ToLower(config.Alertmanager.MinimumPriority)] || falcopayload.Rule == "Test rule") {
		go alertmanagerClient.AlertmanagerPost(falcopayload)
	}
	if config.Elasticsearch.HostPort != "" && (priorityMap[strings.ToLower(falcopayload.Priority)] >= priorityMap[strings.ToLower(config.Elasticsearch.MinimumPriority)] || falcopayload.Rule == "Test rule") {
		go elasticsearchClient.ElasticsearchPost(falcopayload)
	}
	if config.Influxdb.HostPort != "" && (priorityMap[strings.ToLower(falcopayload.Priority)] >= priorityMap[strings.ToLower(config.Influxdb.MinimumPriority)] || falcopayload.Rule == "Test rule") {
		go influxdbClient.InfluxdbPost(falcopayload)
	}
	if config.Loki.HostPort != "" && (priorityMap[strings.ToLower(falcopayload.Priority)] >= priorityMap[strings.ToLower(config.Loki.MinimumPriority)] || falcopayload.Rule == "Test rule") {
		go lokiClient.LokiPost(falcopayload)
	}
	if config.Nats.HostPort != "" && (priorityMap[strings.ToLower(falcopayload.Priority)] >= priorityMap[strings.ToLower(config.Nats.MinimumPriority)] || falcopayload.Rule == "Test rule") {
		go natsClient.NatsPublish(falcopayload)
	}
	if config.AWS.Lambda.FunctionName != "" && (priorityMap[strings.ToLower(falcopayload.Priority)] >= priorityMap[strings.ToLower(config.AWS.Lambda.MinimumPriority)] || falcopayload.Rule == "Test rule") {
		go awsClient.InvokeLambda(falcopayload)
	}
	if config.AWS.SQS.URL != "" && (priorityMap[strings.ToLower(falcopayload.Priority)] >= priorityMap[strings.ToLower(config.AWS.SQS.MinimumPriority)] || falcopayload.Rule == "Test rule") {
		go awsClient.SendMessage(falcopayload)
	}
	if config.AWS.SNS.TopicArn != "" && (priorityMap[strings.ToLower(falcopayload.Priority)] >= priorityMap[strings.ToLower(config.AWS.SNS.MinimumPriority)] || falcopayload.Rule == "Test rule") {
		go awsClient.PublishTopic(falcopayload)
	}
	if config.SMTP.HostPort != "" && (priorityMap[strings.ToLower(falcopayload.Priority)] >= priorityMap[strings.ToLower(config.SMTP.MinimumPriority)] || falcopayload.Rule == "Test rule") {
		go smtpClient.SendMail(falcopayload)
	}
	if config.Opsgenie.APIKey != "" && (priorityMap[strings.ToLower(falcopayload.Priority)] >= priorityMap[strings.ToLower(config.Opsgenie.MinimumPriority)] || falcopayload.Rule == "Test rule") {
		go opsgenieClient.OpsgeniePost(falcopayload)
	}
	if config.Webhook.Address != "" && (priorityMap[strings.ToLower(falcopayload.Priority)] >= priorityMap[strings.ToLower(config.Webhook.MinimumPriority)] || falcopayload.Rule == "Test rule") {
		go webhookClient.WebhookPost(falcopayload)
	}
	if config.Azure.EventHub.Name != "" && (priorityMap[strings.ToLower(falcopayload.Priority)] >= priorityMap[strings.ToLower(config.Azure.EventHub.MinimumPriority)] || falcopayload.Rule == "Test rule") {
		go azureClient.EventHubPost(falcopayload)
	}
        if config.GCPPubSub.Topic != "" && (priorityMap[strings.ToLower(falcopayload.Priority)] >= priorityMap[strings.ToLower(config.GCPPubSub.MinimumPriority)] || falcopayload.Rule == "Test rule") {
                go gcpPubSubClient.GCPPublishTopic(falcopayload)
	}
}
