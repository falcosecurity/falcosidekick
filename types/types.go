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
	Influxdb      influxdbOutputConfig
	AWS           awsOutputConfig
	Customfields  map[string]string
}

type slackOutputConfig struct {
	WebhookURL      string
	Footer          string
	Icon            string
	OutputFormat    string
	MinimumPriority string
}

type datadogOutputConfig struct {
	APIKey          string
	MinimumPriority string
}

type alertmanagerOutputConfig struct {
	HostPort        string
	MinimumPriority string
}

type elasticsearchOutputConfig struct {
	HostPort        string
	Index           string
	Type            string
	MinimumPriority string
	Suffix          string
}

type influxdbOutputConfig struct {
	HostPort        string
	Database        string
	User            string
	Password        string
	MinimumPriority string
}

type awsOutputConfig struct {
	Region          string
	AccessKeyID     string
	SecretAccessKey string
	Lambda          AWSLambdaConfig
}

type AWSLambdaConfig struct {
	FunctionName    string
	InvocationType  string
	LogType         string
	MinimumPriority string
}

type Statistics struct {
	Requests      *expvar.Map
	Slack         *expvar.Map
	Datadog       *expvar.Map
	Alertmanager  *expvar.Map
	Elasticsearch *expvar.Map
	Influxdb      *expvar.Map
	AWSLambda     *expvar.Map
	AWSSQS        *expvar.Map
	// AWSSNS        *expvar.Map
}
