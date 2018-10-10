package main

import (
	"log"
	"net/http"
	"os"
	"strconv"
)

// Env variables
var port string

func init() {
	port = "2801"
	if lport, err := strconv.Atoi(os.Getenv("LISTEN_PORT")); err == nil {
		if lport > 0 && lport < 65536 {
			port = os.Getenv("LISTEN_PORT")
		} else {
			log.Fatalf("[ERROR] : Bad port number\n")
		}
	}
	configText := "[INFO] : Outputs configuration : "
	if os.Getenv("SLACK_TOKEN") != "" {
		configText += "Slack=enabled, "
	} else {
		configText += "Slack=disabled, "
	}
	if os.Getenv("DATADOG_TOKEN") != "" {
		configText += "Datadog=enabled"
	} else {
		configText += "Datadog=disabled"
	}
	log.Printf("%v\n", configText)
}

func main() {
	http.HandleFunc("/", mainHandler)
	http.HandleFunc("/ping", pingHandler)
	http.HandleFunc("/checkpayload", checkpayloadHandler)

	log.Printf("[INFO] : Falco Sidekick is up and listening on port %v\n", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("[ERROR] : %v\n", err.Error())
	}
}
