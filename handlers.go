package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"os"

	"./outputs"
	"./types"
)

// Print falco's payload in stdout (for debug) of daemon
func payloadHandler(w http.ResponseWriter, r *http.Request) {
	// Read body
	requestDump, err := httputil.DumpRequest(r, true)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(requestDump))

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
		http.Error(w, err.Error(), 400)
		return
	}

	if os.Getenv("SLACK_TOKEN") != "" {
		go outputs.SlackPost(falcopayload)
	}
	if os.Getenv("DATADOG_TOKEN") != "" {
		go outputs.DatadogPost(falcopayload)
	}
}

// pingHandler in a simple handler to test if daemon responds
func pingHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("pong\n"))
}
