package main

import (
	"fmt"
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
	http.HandleFunc("/checkPayload", payloadHandler)

	fmt.Println("Falco Sidekick is up and listening on port " + port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		panic(err)
	}
}
