package types

import (
	"time"
)

// FalcoPayload
type FalcoPayload struct {
	Output       string                 `json:"output"`
	Priority     string                 `json:"priority"`
	Rule         string                 `json:"rule"`
	Time         time.Time              `json:"time"`
	OutputFields map[string]interface{} `json:"output_fields"`
}

type Configuration struct {
	Listen_Port  int
	Debug        bool
	Slack        slackOutputConfig
	Datadog      datadogOutputConfig
	Alertmanager alertmanagerOutputConfig
}

type slackOutputConfig struct {
	// Enabled       bool
	Webhook_URL   string
	Footer        string
	Icon          string
	Output_Format string
}

type datadogOutputConfig struct {
	// Enabled bool
	API_Key string
}

type alertmanagerOutputConfig struct {
	// Enabled   bool
	Host_Port string
}
