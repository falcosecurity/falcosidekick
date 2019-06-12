package types

import (
	"expvar"
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
	ListenPort    int
	Debug         bool
	Slack         slackOutputConfig
	Datadog       datadogOutputConfig
	Alertmanager  alertmanagerOutputConfig
	Elasticsearch elasticsearchOutputConfig
	Customfields  map[string]interface{}
}

type slackOutputConfig struct {
	// Enabled       bool
	WebhookURL   string
	Footer       string
	Icon         string
	OutputFormat string
}

type datadogOutputConfig struct {
	// Enabled bool
	APIKey string
}

type alertmanagerOutputConfig struct {
	// Enabled   bool
	HostPort string
}

type elasticsearchOutputConfig struct {
	// Enabled   bool
	HostPort string
	Index    string
	Type     string
}

type Statistics struct {
	Requests      *expvar.Map
	Slack         *expvar.Map
	Datadog       *expvar.Map
	Alertmanager  *expvar.Map
	Elasticsearch *expvar.Map
}
