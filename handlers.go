package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/Issif/falcosidekick/types"
)

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

	falcopayload.OutputFields = make(map[string]interface{})
	if len(config.Customfields) > 0 {
		for key,value := range config.Customfields {
			falcopayload.OutputFields[key] = value
		}
	}
	
	stats.Requests.Add("accepted", 1)

	if config.Debug == true {
		body, _ := json.Marshal(falcopayload)
		log.Printf("[DEBUG] : Falco's payload : %v", string(body))
	}

	if config.Slack.WebhookURL != "" {
		go slackClient.SlackPost(falcopayload)
	}
	if config.Datadog.APIKey != "" {
		go datadogClient.DatadogPost(falcopayload)
	}
	if config.Alertmanager.HostPort != "" {
		go alertmanagerClient.AlertmanagerPost(falcopayload)
	}
	if config.Elasticsearch.HostPort != "" {
		go elasticsearchClient.ElasticsearchPost(falcopayload)
	}
}

// pingHandler is a simple handler to test if daemon is UP.
func pingHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("pong\n"))
}

// testHandler sends a test event to all enabled outputs.
func testHandler(w http.ResponseWriter, r *http.Request) {
	testEvent := `{"output":"This is a test from falcosidekick","priority":"Debug","rule":"Test rule", "time":"`+time.Now().UTC().Format(time.RFC3339)+`","outputfields": {"proc.name":"falcosidekick","user.name":"falcosidekick"}}`

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
