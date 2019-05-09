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
	enableOutputsText := "[INFO] : Enable Outputs : "
	disableOutputsText := "[INFO] : Disable Outputs : "
	if os.Getenv("SLACK_TOKEN") != "" {
		enableOutputsText += "Slack, "
	} else {
		disableOutputsText += "Slack, "
	}
	if os.Getenv("DATADOG_TOKEN") != "" {
		enableOutputsText += "Datadog, "
	} else {
		disableOutputsText += "Datadog, "
	}
	if os.Getenv("ALERTMANAGER_HOST_PORT") != "" {
		enableOutputsText += "AlertManager"
	} else {
		disableOutputsText += "AlertManager"
	}

	log.Printf("%v\n", enableOutputsText)
	log.Printf("%v\n", disableOutputsText)
}

func main() {
	http.HandleFunc("/", mainHandler)
	http.HandleFunc("/ping", pingHandler)
	http.HandleFunc("/test", testHandler)

	log.Printf("[INFO] : Falco Sidekick is up and listening on port %v\n", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("[ERROR] : %v\n", err.Error())
	} else {
	}
}
