package main

import (
	"log"
	"net/http"
	"os"
)

// Env variables
var port string

func init() {

	port, _ = os.LookupEnv("LISTEN_PORT")
	if port == "" {
		port = "2801"
	}
}

func main() {
	http.HandleFunc("/", mainHandler)
	http.HandleFunc("/ping", pingHandler)
	http.HandleFunc("/checkpayload", checkpayloadHandler)

	log.Printf("Falco Sidekick is up and listening on port %v\n", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("[ERROR] : %v\n", err.Error())
	}
}
