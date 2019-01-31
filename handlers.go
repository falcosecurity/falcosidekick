package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/Issif/falcosidekick/outputs"
	"github.com/Issif/falcosidekick/types"
)

// Print falco's payload in stdout (for debug) of daemon
func checkpayloadHandler(w http.ResponseWriter, r *http.Request) {
	// Read body
	requestDump, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.Write([]byte(err.Error() + "\n"))
		log.Printf("[ERROR] : %v\n", err.Error())
	}
	w.Write([]byte(requestDump))
	log.Printf("[DEBUG] : Paylod =  %v\n", string(requestDump))
}

// mainHandler
func mainHandler(w http.ResponseWriter, r *http.Request) {

	var falcopayload types.FalcoPayload

	if r.Body == nil {
		http.Error(w, "Please send a valid request body", 400)
		return
	}

	err := json.NewDecoder(r.Body).Decode(&falcopayload)
	if err != nil && err.Error() != "EOF" {
		http.Error(w, "Please send a valid request body : "+err.Error(), 400)
		return
	}

	if os.Getenv("SLACK_TOKEN") != "" {
		go outputs.SlackPost(falcopayload)
	}
	if os.Getenv("DATADOG_TOKEN") != "" {
		go outputs.DatadogPost(falcopayload)
	}
	if os.Getenv("ALERTMANAGER_HOST_PORT") != "" {
		go outputs.AlertmanagerPost(falcopayload)
	}
}

// pingHandler in a simple handler to test if daemon responds
func pingHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("pong\n"))
}
