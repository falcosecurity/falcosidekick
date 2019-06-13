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
	Influxdb      InfluxdbOutputConfig
	Customfields  map[string]string
}

type slackOutputConfig struct {
	// Enabled       bool
	WebhookURL      string
	Footer          string
	Icon            string
	OutputFormat    string
	MinimumPriority string
}

type datadogOutputConfig struct {
	// Enabled bool
	APIKey          string
	MinimumPriority string
}

type alertmanagerOutputConfig struct {
	// Enabled   bool
	HostPort        string
	MinimumPriority string
}

type elasticsearchOutputConfig struct {
	// Enabled   bool
	HostPort        string
	Index           string
	Type            string
	MinimumPriority string
}

type InfluxdbOutputConfig struct {
	// Enabled   bool
	HostPort        string
	Database        string
	User            string
	Password        string
	MinimumPriority string
}

type Statistics struct {
	Requests      *expvar.Map
	Slack         *expvar.Map
	Datadog       *expvar.Map
	Alertmanager  *expvar.Map
	Elasticsearch *expvar.Map
	Influxdb      *expvar.Map
}
