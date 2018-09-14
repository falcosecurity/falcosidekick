package main

import (
	"time"
)

// FalcoPayload
type falcoPayload struct {
	Output       string                 `json:"output"`
	Priority     string                 `json:"priority"`
	Rule         string                 `json:"rule"`
	Time         time.Time              `json:"time"`
	OutputFields map[string]interface{} `json:"output_fields"`
}
