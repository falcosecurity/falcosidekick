package main

import (
	"fmt"
	"net/http"
	"os"
)

// Env variables
var slackToken string
var datadogToken string
var port string

func init() {
	slackToken, _ = os.LookupEnv("SLACK_TOKEN")
	datadogToken, _ = os.LookupEnv("DATADOG_TOKEN")
	port, _ = os.LookupEnv("LISTEN_PORT")
	if port == "" {
		port = "2801"
	}
}

func main() {
	http.HandleFunc("/", mainHandler)
	http.HandleFunc("/ping", pingHandler)
	http.HandleFunc("/checkPayload", payloadHandler)

	fmt.Println("Falco Sidekick is up and listening on port " + port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		panic(err)
	}
}
