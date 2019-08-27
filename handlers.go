package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Issif/falcosidekick/types"
)

func getPriorityMap() map[string]int {
	return map[string]int{
		"emergency":      8,
		"alert":          7,
		"critical":       6,
		"error":          5,
		"warning":        4,
		"notice":         3,
		"informationnal": 2,
		"debug":          1,
		"":               0,
	}
}

// mainHandler is Falco Sidekick main handler (default).
func mainHandler(w http.ResponseWriter, r *http.Request) {

	var falcopayload types.FalcoPayload

	stats.Requests.Add("total", 1)

	if r.Body == nil {
		http.Error(w, "Please send a valid request body", 400)
		stats.Requests.Add("rejected", 1)
		return
	}

	err := json.NewDecoder(r.Body).Decode(&falcopayload)
	if err != nil && err.Error() != "EOF" || len(falcopayload.Output) == 0 {
		http.Error(w, "Please send a valid request body : "+err.Error(), 400)
		stats.Requests.Add("rejected", 1)
		return
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

	stats.Requests.Add("accepted", 1)

	if config.Debug == true {
		body, _ := json.Marshal(falcopayload)
		log.Printf("[DEBUG] : Falco's payload : %v", string(body))
	}

	priorityMap := getPriorityMap()

	if config.Slack.WebhookURL != "" && (priorityMap[strings.ToLower(falcopayload.Priority)] >= priorityMap[strings.ToLower(config.Slack.MinimumPriority)] || falcopayload.Rule == "Test rule") {
		go slackClient.SlackPost(falcopayload)
	}
	if config.Teams.WebhookURL != "" && (priorityMap[strings.ToLower(falcopayload.Priority)] >= priorityMap[strings.ToLower(config.Teams.MinimumPriority)] || falcopayload.Rule == "Test rule") {
		go teamsClient.TeamsPost(falcopayload)
	}
	if config.Datadog.APIKey != "" && (priorityMap[strings.ToLower(falcopayload.Priority)] >= priorityMap[strings.ToLower(config.Datadog.MinimumPriority)] || falcopayload.Rule == "Test rule") {
		go datadogClient.DatadogPost(falcopayload)
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
	if config.AWS.Lambda.FunctionName != "" && (priorityMap[strings.ToLower(falcopayload.Priority)] >= priorityMap[strings.ToLower(config.AWS.Lambda.MinimumPriority)] || falcopayload.Rule == "Test rule") {
		go awsClient.InvokeLambda(falcopayload)
	}
	if config.AWS.SQS.URL != "" && (priorityMap[strings.ToLower(falcopayload.Priority)] >= priorityMap[strings.ToLower(config.AWS.SQS.MinimumPriority)] || falcopayload.Rule == "Test rule") {
		go awsClient.SendMessage(falcopayload)
	}
	if config.SMTP.HostPort != "" && (priorityMap[strings.ToLower(falcopayload.Priority)] >= priorityMap[strings.ToLower(config.SMTP.MinimumPriority)] || falcopayload.Rule == "Test rule") {
		go smtpClient.SendMail(falcopayload)
	}
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
