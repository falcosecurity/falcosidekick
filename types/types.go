package types

import (
	"encoding/json"
	"expvar"
	"text/template"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// FalcoPayload is a struct to map falco event json
type FalcoPayload struct {
	UUID         string                 `json:"uuid,omitempty"`
	Output       string                 `json:"output"`
	Priority     PriorityType           `json:"priority"`
	Rule         string                 `json:"rule"`
	Time         time.Time              `json:"time"`
	OutputFields map[string]interface{} `json:"output_fields"`
	Source       string                 `json:"source"`
	Tags         []string               `json:"tags,omitempty"`
}

func (f FalcoPayload) String() string {
	j, _ := json.Marshal(f)
	return string(j)
}

// Configuration is a struct to store configuration
type Configuration struct {
	MutualTLSFilesPath string
	Debug              bool
	ListenAddress      string
	ListenPort         int
	Customfields       map[string]string
	Templatedfields    map[string]string
	Prometheus         prometheusOutputConfig
	Slack              SlackOutputConfig
	Cliq               CliqOutputConfig
	Mattermost         MattermostOutputConfig
	Rocketchat         RocketchatOutputConfig
	Teams              teamsOutputConfig
	Datadog            datadogOutputConfig
	Discord            DiscordOutputConfig
	Alertmanager       AlertmanagerOutputConfig
	Elasticsearch      elasticsearchOutputConfig
	Influxdb           influxdbOutputConfig
	Loki               lokiOutputConfig
	Nats               natsOutputConfig
	Stan               stanOutputConfig
	AWS                awsOutputConfig
	SMTP               smtpOutputConfig
	Opsgenie           opsgenieOutputConfig
	Statsd             statsdOutputConfig
	Dogstatsd          statsdOutputConfig
	Webhook            WebhookOutputConfig
	CloudEvents        CloudEventsOutputConfig
	Azure              azureConfig
	GCP                gcpOutputConfig
	Googlechat         GooglechatConfig
	Kafka              kafkaConfig
	KafkaRest          KafkaRestConfig
	Pagerduty          PagerdutyConfig
	Kubeless           kubelessConfig
	Openfaas           openfaasConfig
	WebUI              WebUIOutputConfig
	PolicyReport       PolicyReportConfig
	Rabbitmq           RabbitmqConfig
	Wavefront          WavefrontOutputConfig
	Fission            fissionConfig
	Grafana            grafanaOutputConfig
	Yandex             YandexOutputConfig
	Syslog             SyslogConfig
	NodeRed            NodeRedOutputConfig
	MQTT               MQTTConfig
	Zincsearch         zincsearchOutputConfig
	Gotify             gotifyOutputConfig
}

// SlackOutputConfig represents parameters for Slack
type SlackOutputConfig struct {
	WebhookURL            string
	Channel               string
	Footer                string
	Icon                  string
	Username              string
	OutputFormat          string
	MinimumPriority       string
	MessageFormat         string
	MessageFormatTemplate *template.Template
	CheckCert             bool
	MutualTLS             bool
}

// CliqOutputConfig represents parameters for Zoho Cliq
type CliqOutputConfig struct {
	WebhookURL            string
	Icon                  string
	OutputFormat          string
	MinimumPriority       string
	MessageFormat         string
	MessageFormatTemplate *template.Template
	UseEmoji              bool
	CheckCert             bool
	MutualTLS             bool
}

// RocketchatOutputConfig .
type RocketchatOutputConfig struct {
	WebhookURL            string
	Footer                string
	Icon                  string
	Username              string
	OutputFormat          string
	MinimumPriority       string
	MessageFormat         string
	MessageFormatTemplate *template.Template
	CheckCert             bool
	MutualTLS             bool
}

// MattermostOutputConfig represents parameters for Mattermost
type MattermostOutputConfig struct {
	WebhookURL            string
	Footer                string
	Icon                  string
	Username              string
	OutputFormat          string
	MinimumPriority       string
	MessageFormat         string
	MessageFormatTemplate *template.Template
	CheckCert             bool
	MutualTLS             bool
}

type WavefrontOutputConfig struct {
	EndpointType         string // direct or proxy
	EndpointHost         string // Endpoint hostname (only IP or hostname)
	EndpointToken        string // Token for API access. Only for direct mode
	EndpointMetricPort   int    // Port to send metrics. Only for proxy mode
	MetricName           string // The Name of the metric
	FlushIntervalSeconds int    // Time between flushes.
	BatchSize            int    // BatchSize to send. Only for direct mode
	MinimumPriority      string
}

type teamsOutputConfig struct {
	WebhookURL      string
	ActivityImage   string
	OutputFormat    string
	MinimumPriority string
	CheckCert       bool
	MutualTLS       bool
}

type datadogOutputConfig struct {
	APIKey          string
	Host            string
	MinimumPriority string
	CheckCert       bool
	MutualTLS       bool
}

// DiscordOutputConfig .
type DiscordOutputConfig struct {
	WebhookURL      string
	MinimumPriority string
	Icon            string
	CheckCert       bool
	MutualTLS       bool
}

type AlertmanagerOutputConfig struct {
	HostPort         string
	MinimumPriority  string
	CheckCert        bool
	MutualTLS        bool
	Endpoint         string
	ExpiresAfter     int
	ExtraLabels      map[string]string
	ExtraAnnotations map[string]string
}

type elasticsearchOutputConfig struct {
	HostPort        string
	Index           string
	Type            string
	MinimumPriority string
	Suffix          string
	Username        string
	Password        string
	CheckCert       bool
	MutualTLS       bool
}

type influxdbOutputConfig struct {
	HostPort        string
	Database        string
	Organization    string
	Bucket          string
	Precision       string
	User            string
	Password        string
	Token           string
	MinimumPriority string
	CheckCert       bool
	MutualTLS       bool
}

type lokiOutputConfig struct {
	HostPort        string
	MinimumPriority string
	CheckCert       bool
	MutualTLS       bool
	Tenant          string
	Endpoint        string
	ExtraLabels     string
	ExtraLabelsList []string
}

type prometheusOutputConfig struct {
	ExtraLabels     string
	ExtraLabelsList []string
}

type natsOutputConfig struct {
	HostPort        string
	MinimumPriority string
	CheckCert       bool
	MutualTLS       bool
}

type stanOutputConfig struct {
	HostPort        string
	ClusterID       string
	ClientID        string
	MinimumPriority string
	CheckCert       bool
	MutualTLS       bool
}

type awsOutputConfig struct {
	Region          string
	AccessKeyID     string
	SecretAccessKey string
	Lambda          awsLambdaConfig
	SQS             awsSQSConfig
	SNS             awsSNSConfig
	S3              awsS3Config
	CloudWatchLogs  awsCloudWatchLogs
	Kinesis         awsKinesisConfig
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

type awsCloudWatchLogs struct {
	LogGroup        string
	LogStream       string
	MinimumPriority string
}

type awsS3Config struct {
	Prefix          string
	Bucket          string
	MinimumPriority string
}

type awsKinesisConfig struct {
	StreamName      string
	MinimumPriority string
}

type smtpOutputConfig struct {
	HostPort        string
	AuthMechanism   string
	User            string
	Password        string
	Token           string
	Identity        string
	Trace           string
	From            string
	To              string
	OutputFormat    string
	MinimumPriority string
}

type opsgenieOutputConfig struct {
	Region          string
	APIKey          string
	MinimumPriority string
	CheckCert       bool
	MutualTLS       bool
}

// WebhookOutputConfig represents parameters for Webhook
type WebhookOutputConfig struct {
	Address         string
	CustomHeaders   map[string]string
	MinimumPriority string
	CheckCert       bool
	MutualTLS       bool
}

// NodeRedOutputConfig represents parameters for Node-RED
type NodeRedOutputConfig struct {
	Address         string
	User            string
	Password        string
	CustomHeaders   map[string]string
	MinimumPriority string
	CheckCert       bool
}

// CloudEventsOutputConfig represents parameters for CloudEvents
type CloudEventsOutputConfig struct {
	Address         string
	Extensions      map[string]string
	MinimumPriority string
	CheckCert       bool
	MutualTLS       bool
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

type gcpCloudRun struct {
	Endpoint        string
	JWT             string
	MinimumPriority string
}

type gcpOutputConfig struct {
	Credentials      string
	WorkloadIdentity bool
	PubSub           gcpPubSub
	Storage          gcpStorage
	CloudFunctions   gcpCloudFunctions
	CloudRun         gcpCloudRun
}

type gcpCloudFunctions struct {
	Name            string
	MinimumPriority string
}

type gcpPubSub struct {
	ProjectID       string
	Topic           string
	MinimumPriority string
}

type gcpStorage struct {
	Bucket          string
	Prefix          string
	MinimumPriority string
}

// GooglechatConfig represents parameters for Google chat
type GooglechatConfig struct {
	WebhookURL            string
	OutputFormat          string
	MinimumPriority       string
	MessageFormat         string
	MessageFormatTemplate *template.Template
	CheckCert             bool
	MutualTLS             bool
}

type kafkaConfig struct {
	HostPort        string
	Topic           string
	MinimumPriority string
}

type KafkaRestConfig struct {
	Address         string
	Version         int
	MinimumPriority string
	CheckCert       bool
	MutualTLS       bool
}

type PagerdutyConfig struct {
	RoutingKey      string
	MinimumPriority string
	CheckCert       bool
	MutualTLS       bool
}

type kubelessConfig struct {
	Namespace       string
	Function        string
	Port            int
	Kubeconfig      string
	MinimumPriority string
	CheckCert       bool
	MutualTLS       bool
}

type openfaasConfig struct {
	GatewayNamespace  string
	GatewayService    string
	FunctionName      string
	FunctionNamespace string
	GatewayPort       int
	Kubeconfig        string
	MinimumPriority   string
	CheckCert         bool
	MutualTLS         bool
}

// WebUIOutputConfig represents parameters for WebUI
type WebUIOutputConfig struct {
	URL       string
	CheckCert bool
	MutualTLS bool
}

// PolicyReportConfig represents parameters for policyreport
type PolicyReportConfig struct {
	Enabled         bool
	PruneByPriority bool
	Kubeconfig      string
	MinimumPriority string
	MaxEvents       int
}

// RabbitmqConfig represents parameters for rabbitmq
type RabbitmqConfig struct {
	URL             string
	Queue           string
	MinimumPriority string
}

// grafanaOutputConfig represents parameters for Grafana
type grafanaOutputConfig struct {
	HostPort        string
	APIKey          string
	DashboardID     int
	PanelID         int
	AllFieldsAsTags bool
	CheckCert       bool
	MutualTLS       bool
	MinimumPriority string
}

type YandexOutputConfig struct {
	AccessKeyID     string
	SecretAccessKey string
	Region          string
	S3              YandexS3Config
	DataStreams     YandexDataStreamsConfig
}
type YandexS3Config struct {
	Endpoint        string
	Prefix          string
	Bucket          string
	MinimumPriority string
}
type YandexDataStreamsConfig struct {
	Endpoint        string
	StreamName      string
	MinimumPriority string
}

// SyslogConfig represents config parameters for the syslog client
// Host: the remote syslog host. It can be either an IP address or a domain.
// Port: the remote port address. Ex: 514.
// Protocol: the type of transfer protocol to use. It should be either "tcp" or "udp".
type SyslogConfig struct {
	Host            string
	Port            string
	Protocol        string
	MinimumPriority string
}

// MQTTConfig represents config parameters for the MQTT client
type MQTTConfig struct {
	Broker          string
	Topic           string
	QOS             int
	Retained        bool
	User            string
	Password        string
	CheckCert       bool
	MinimumPriority string
}

// fissionConfig represents config parameters for Fission
type fissionConfig struct {
	RouterNamespace string
	RouterService   string
	RouterPort      int
	Function        string
	KubeConfig      string
	MinimumPriority string
	CheckCert       bool
	MutualTLS       bool
}

// zincsearchOutputConfig represents config parameters for Zincsearch
type zincsearchOutputConfig struct {
	HostPort        string
	Index           string
	Username        string
	Password        string
	CheckCert       bool
	MinimumPriority string
}

// gotifyOutputConfig represents config parameters for Gotify
type gotifyOutputConfig struct {
	HostPort        string
	Token           string
	Format          string
	CheckCert       bool
	MinimumPriority string
}

// Statistics is a struct to store stastics
type Statistics struct {
	Requests          *expvar.Map
	FIFO              *expvar.Map
	GRPC              *expvar.Map
	Falco             *expvar.Map
	Slack             *expvar.Map
	Mattermost        *expvar.Map
	Rocketchat        *expvar.Map
	Teams             *expvar.Map
	Datadog           *expvar.Map
	Discord           *expvar.Map
	Alertmanager      *expvar.Map
	Elasticsearch     *expvar.Map
	Loki              *expvar.Map
	Nats              *expvar.Map
	Stan              *expvar.Map
	Influxdb          *expvar.Map
	AWSLambda         *expvar.Map
	AWSSQS            *expvar.Map
	AWSSNS            *expvar.Map
	AWSCloudWatchLogs *expvar.Map
	AWSS3             *expvar.Map
	AWSKinesis        *expvar.Map
	SMTP              *expvar.Map
	Opsgenie          *expvar.Map
	Statsd            *expvar.Map
	Dogstatsd         *expvar.Map
	Webhook           *expvar.Map
	AzureEventHub     *expvar.Map
	GCPPubSub         *expvar.Map
	GCPStorage        *expvar.Map
	GCPCloudFunctions *expvar.Map
	GCPCloudRun       *expvar.Map
	GoogleChat        *expvar.Map
	Kafka             *expvar.Map
	KafkaRest         *expvar.Map
	Pagerduty         *expvar.Map
	CloudEvents       *expvar.Map
	Kubeless          *expvar.Map
	Openfaas          *expvar.Map
	WebUI             *expvar.Map
	Rabbitmq          *expvar.Map
	Wavefront         *expvar.Map
	Fission           *expvar.Map
	Grafana           *expvar.Map
	YandexS3          *expvar.Map
	YandexDataStreams *expvar.Map
	Syslog            *expvar.Map
	Cliq              *expvar.Map
	PolicyReport      *expvar.Map
	NodeRed           *expvar.Map
	MQTT              *expvar.Map
	Zincsearch        *expvar.Map
	Gotify            *expvar.Map
}

// PromStatistics is a struct to store prometheus metrics
type PromStatistics struct {
	Falco   *prometheus.CounterVec
	Inputs  *prometheus.CounterVec
	Outputs *prometheus.CounterVec
}
