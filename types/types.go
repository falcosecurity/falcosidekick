package types

import (
	"expvar"
	"text/template"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// FalcoPayload is a struct to map falco event json
type FalcoPayload struct {
	Output       string                 `json:"output"`
	Priority     string                 `json:"priority"`
	Rule         string                 `json:"rule"`
	Time         time.Time              `json:"time"`
	OutputFields map[string]interface{} `json:"output_fields"`
}

// Configuration is a struct to store configuration
type Configuration struct {
	ListenPort    int
	Debug         bool
	Slack         SlackOutputConfig
	Mattermost    mattermostOutputConfig
	Rocketchat    rocketchatOutputConfig
	Teams         teamsOutputConfig
	Datadog       datadogOutputConfig
	Discord       discordOutputConfig
	Alertmanager  alertmanagerOutputConfig
	Elasticsearch elasticsearchOutputConfig
	Influxdb      influxdbOutputConfig
	Loki          lokiOutputConfig
	Nats          natsOutputConfig
	AWS           awsOutputConfig
	SMTP          smtpOutputConfig
	Opsgenie      opsgenieOutputConfig
	Statsd        statsdOutputConfig
	Dogstatsd     statsdOutputConfig
	Webhook       WebhookOutputConfig
	Azure         azureConfig
	Customfields  map[string]string
	CheckCert     bool
}

// SlackOutputConfig represents parameters for Slack
type SlackOutputConfig struct {
	WebhookURL            string
	Footer                string
	Icon                  string
	Username              string
	OutputFormat          string
	MinimumPriority       string
	MessageFormat         string
	MessageFormatTemplate *template.Template
}

type rocketchatOutputConfig struct {
	WebhookURL            string
	Footer                string
	Icon                  string
	Username              string
	OutputFormat          string
	MinimumPriority       string
	MessageFormat         string
	MessageFormatTemplate *template.Template
}

type mattermostOutputConfig struct {
	WebhookURL            string
	Footer                string
	Icon                  string
	Username              string
	OutputFormat          string
	MinimumPriority       string
	MessageFormat         string
	MessageFormatTemplate *template.Template
}

type teamsOutputConfig struct {
	WebhookURL      string
	ActivityImage   string
	OutputFormat    string
	MinimumPriority string
}

type datadogOutputConfig struct {
	APIKey          string
	Host            string
	MinimumPriority string
}

type discordOutputConfig struct {
	WebhookURL      string
	MinimumPriority string
	Icon            string
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

type lokiOutputConfig struct {
	HostPort        string
	MinimumPriority string
}

type natsOutputConfig struct {
	HostPort        string
	MinimumPriority string
}

type awsOutputConfig struct {
	Region          string
	AccessKeyID     string
	SecretAccessKey string
	Lambda          awsLambdaConfig
	SQS             awsSQSConfig
	SNS             awsSNSConfig
}

type awsLambdaConfig struct {
	FunctionName    string
	InvocationType  string
	LogType         string
	MinimumPriority string
}

type awsSQSConfig struct {
	URL             string
	MinimumPriority string
}

type awsSNSConfig struct {
	TopicArn        string
	RawJSON         bool
	MinimumPriority string
}

type smtpOutputConfig struct {
	HostPort        string
	User            string
	Password        string
	From            string
	To              string
	OutputFormat    string
	MinimumPriority string
}

type opsgenieOutputConfig struct {
	Region          string
	APIKey          string
	MinimumPriority string
}

// WebhookOutputConfig represents parameters for Webhook
type WebhookOutputConfig struct {
	Address         string
	CustomHeaders   map[string]string
	MinimumPriority string
}

type statsdOutputConfig struct {
	Forwarder string
	Namespace string
	Tags      []string
}

type azureConfig struct {
	EventHub eventHub
}

type eventHub struct {
	Namespace       string
	Name            string
	MinimumPriority string
}

// Statistics is a struct to store stastics
type Statistics struct {
	Requests      *expvar.Map
	FIFO          *expvar.Map
	GRPC          *expvar.Map
	Falco         *expvar.Map
	Slack         *expvar.Map
	Mattermost    *expvar.Map
	Rocketchat    *expvar.Map
	Teams         *expvar.Map
	Datadog       *expvar.Map
	Discord       *expvar.Map
	Alertmanager  *expvar.Map
	Elasticsearch *expvar.Map
	Loki          *expvar.Map
	Nats          *expvar.Map
	Influxdb      *expvar.Map
	AWSLambda     *expvar.Map
	AWSSQS        *expvar.Map
	AWSSNS        *expvar.Map
	SMTP          *expvar.Map
	Opsgenie      *expvar.Map
	Statsd        *expvar.Map
	Dogstatsd     *expvar.Map
	Webhook       *expvar.Map
	AzureEventHub *expvar.Map
}

// PromStatistics is a struct to store prometheus metrics
type PromStatistics struct {
	Falco   *prometheus.CounterVec
	Inputs  *prometheus.CounterVec
	Outputs *prometheus.CounterVec
}
