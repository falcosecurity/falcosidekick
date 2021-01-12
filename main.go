package main

import (
	"log"

	"github.com/falcosecurity/falcosidekick/pkg/sidekick"
)

func main() {

	if err := sidekick.Start(); err != nil {
		log.Fatalf("[ERROR] : %v\n", err.Error())
	}
}
