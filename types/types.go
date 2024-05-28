// SPDX-License-Identifier: MIT OR Apache-2.0

package types

import (
	"context"
	"encoding/json"
	"expvar"
	"text/template"
	"time"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/embano1/memlog"
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
	Hostname     string                 `json:"hostname,omitempty"`
}

func (f FalcoPayload) String() string {
	j, _ := json.Marshal(f)
	return string(j)
}

func (f FalcoPayload) Check() bool {
	if f.Priority.String() == "" {
		return false
	}
	if f.Rule == "" {
		return false
	}
	if f.Time.IsZero() {
		return false
	}
	if len(f.OutputFields) == 0 {
		return false
	}
	return true
}

// Configuration is a struct to store configuration
type Configuration struct {
	MutualTLSFilesPath string
	MutualTLSClient    MutualTLSClient
	TLSClient          TLSClient
	TLSServer          TLSServer
	Debug              bool
	ListenAddress      string
	ListenPort         int
	BracketReplacer    string
	OutputFieldFormat  string
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
	Elasticsearch      ElasticsearchOutputConfig
	Quickwit           QuickwitOutputConfig
	Influxdb           influxdbOutputConfig
	Loki               LokiOutputConfig
	SumoLogic          SumoLogicOutputConfig
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
	GCP                GcpOutputConfig
	Googlechat         GooglechatConfig
	Kafka              kafkaConfig
	KafkaRest          KafkaRestConfig
	Pagerduty          PagerdutyConfig
	Kubeless           kubelessConfig
	Openfaas           openfaasConfig
	Tekton             tektonConfig
	WebUI              WebUIOutputConfig
	PolicyReport       PolicyReportConfig
	Rabbitmq           RabbitmqConfig
	Wavefront          WavefrontOutputConfig
	Fission            fissionConfig
	Grafana            GrafanaOutputConfig
	GrafanaOnCall      GrafanaOnCallOutputConfig
	Yandex             YandexOutputConfig
	Syslog             SyslogConfig
	NodeRed            NodeRedOutputConfig
	MQTT               MQTTConfig
	Zincsearch         zincsearchOutputConfig
	Gotify             gotifyOutputConfig
	Spyderbat          SpyderbatConfig
	TimescaleDB        TimescaleDBConfig
	Redis              RedisConfig
	Telegram           TelegramConfig
	N8N                N8NConfig
	OpenObserve        OpenObserveConfig
	Dynatrace          DynatraceOutputConfig
	OTLP               OTLPOutputConfig
}

// InitClientArgs represent a client parameters for initialization
type InitClientArgs struct {
	Config          *Configuration
	Stats           *Statistics
	PromStats       *PromStatistics
	StatsdClient    *statsd.Client
	DogstatsdClient *statsd.Client
}

// MutualTLSClient represents parameters for mutual TLS as client
type MutualTLSClient struct {
	CertFile   string
	KeyFile    string
	CaCertFile string
}

// MutualTLSClient represents parameters for global TLS client options
type TLSClient struct {
	CaCertFile string
}

// TLSServer represents parameters for TLS Server
type TLSServer struct {
	Deploy     bool
	CertFile   string
	KeyFile    string
	MutualTLS  bool
	CaCertFile string
	NoTLSPort  int
	NoTLSPaths []string
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

type ThresholdConfig struct {
	Value    int64        `json:"value" yaml:"value"`
	Priority PriorityType `json:"priority" yaml:"priority"`
}

type AlertmanagerOutputConfig struct {
	HostPort                 string
	MinimumPriority          string
	CheckCert                bool
	MutualTLS                bool
	Endpoint                 string
	ExpiresAfter             int
	ExtraLabels              map[string]string
	ExtraAnnotations         map[string]string
	CustomSeverityMap        map[PriorityType]string
	DropEventThresholds      string
	DropEventThresholdsList  []ThresholdConfig
	DropEventDefaultPriority string
	CustomHeaders            map[string]string
}

type ElasticsearchOutputConfig struct {
	HostPort        string
	Index           string
	Type            string
	MinimumPriority string
	Suffix          string
	Username        string
	Password        string
	CheckCert       bool
	MutualTLS       bool
	CustomHeaders   map[string]string
}

type QuickwitOutputConfig struct {
	HostPort        string
	ApiEndpoint     string
	Index           string
	Version         string
	CustomHeaders   map[string]string
	MinimumPriority string
	CheckCert       bool
	MutualTLS       bool
	AutoCreateIndex bool
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

type LokiOutputConfig struct {
	HostPort        string
	User            string
	APIKey          string
	MinimumPriority string
	CheckCert       bool
	MutualTLS       bool
	Tenant          string
	Endpoint        string
	ExtraLabels     string
	ExtraLabelsList []string
	CustomHeaders   map[string]string
}

type SumoLogicOutputConfig struct {
	MinimumPriority string
	ReceiverURL     string
	SourceCategory  string
	SourceHost      string
	Name            string
	CheckCert       bool
	MutualTLS       bool
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
	RoleARN         string
	ExternalID      string
	CheckIdentity   bool
	Lambda          awsLambdaConfig
	SQS             awsSQSConfig
	SNS             awsSNSConfig
	S3              awsS3Config
	SecurityLake    awsSecurityLakeConfig
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
	Endpoint        string
	ObjectCannedACL string
}

type awsKinesisConfig struct {
	StreamName      string
	MinimumPriority string
}

type awsSecurityLakeConfig struct {
	Bucket          string
	Region          string
	Prefix          string
	AccountID       string
	Interval        uint
	BatchSize       uint
	MinimumPriority string
	Ctx             context.Context
	Memlog          *memlog.Log
	ReadOffset      *memlog.Offset
	WriteOffset     *memlog.Offset
}

type smtpOutputConfig struct {
	HostPort        string
	TLS             bool
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
	Method          string
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

type GcpOutputConfig struct {
	Credentials      string
	WorkloadIdentity bool
	PubSub           GcpPubSub
	Storage          gcpStorage
	CloudFunctions   gcpCloudFunctions
	CloudRun         gcpCloudRun
}

type gcpCloudFunctions struct {
	Name            string
	MinimumPriority string
}

type GcpPubSub struct {
	ProjectID        string
	Topic            string
	MinimumPriority  string
	CustomAttributes map[string]string
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
	SASL            string
	TLS             bool
	Username        string
	Password        string
	Balancer        string
	ClientID        string
	Compression     string
	Async           bool
	RequiredACKs    string
	TopicCreation   bool
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
	Region          string
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

type tektonConfig struct {
	EventListener   string
	MinimumPriority string
	CheckCert       bool
	MutualTLS       bool
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

// GrafanaOutputConfig represents parameters for Grafana
type GrafanaOutputConfig struct {
	HostPort        string
	APIKey          string
	DashboardID     int
	PanelID         int
	AllFieldsAsTags bool
	CheckCert       bool
	MutualTLS       bool
	MinimumPriority string
	CustomHeaders   map[string]string
}

// GrafanaOnCallOutputConfig represents parameters for Grafana OnCall
type GrafanaOnCallOutputConfig struct {
	WebhookURL      string
	CheckCert       bool
	MutualTLS       bool
	MinimumPriority string
	CustomHeaders   map[string]string
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
	Format          string
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

type SpyderbatConfig struct {
	OrgUID            string
	APIKey            string
	APIUrl            string
	Source            string
	SourceDescription string
	MinimumPriority   string
}

type TimescaleDBConfig struct {
	Host            string
	Port            string
	User            string
	Password        string
	Database        string
	HypertableName  string
	MinimumPriority string
}

// RedisConfig represents config parameters for Redis
type RedisConfig struct {
	Address         string
	Password        string
	Database        int
	StorageType     string
	Key             string
	Version         int
	MinimumPriority string
	CheckCert       bool
	MutualTLS       bool
}

// TelegramConfig represents parameters for Telegram
type TelegramConfig struct {
	Token           string
	ChatID          string
	MinimumPriority string
	CheckCert       bool
}

// N8NConfig represents config parameters for N8N
type N8NConfig struct {
	Address         string
	User            string
	Password        string
	HeaderAuthName  string
	HeaderAuthValue string
	MinimumPriority string
	CheckCert       bool
}

type DynatraceOutputConfig struct {
	APIToken        string
	APIUrl          string
	MinimumPriority string
	CheckCert       bool
}

// OpenObserveConfig represents config parameters for OpenObserve
type OpenObserveConfig struct {
	HostPort         string
	OrganizationName string
	StreamName       string
	MinimumPriority  string
	Username         string
	Password         string
	CheckCert        bool
	MutualTLS        bool
	CustomHeaders    map[string]string
}

// OTLPTraces represents config parameters for OTLP Traces
type OTLPTraces struct {
	Endpoint        string
	Protocol        string
	Timeout         int64
	Headers         string
	Duration        int64
	Synced          bool
	ExtraEnvVars    map[string]string
	CheckCert       bool
	MinimumPriority string
}

// OTLPOutputConfig represents config parameters for OTLP
type OTLPOutputConfig struct {
	Traces OTLPTraces
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
	Quickwit          *expvar.Map
	Loki              *expvar.Map
	SumoLogic         *expvar.Map
	Nats              *expvar.Map
	Stan              *expvar.Map
	Influxdb          *expvar.Map
	AWSLambda         *expvar.Map
	AWSSQS            *expvar.Map
	AWSSNS            *expvar.Map
	AWSCloudWatchLogs *expvar.Map
	AWSS3             *expvar.Map
	AWSSecurityLake   *expvar.Map
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
	Tekton            *expvar.Map
	WebUI             *expvar.Map
	Rabbitmq          *expvar.Map
	Wavefront         *expvar.Map
	Fission           *expvar.Map
	Grafana           *expvar.Map
	GrafanaOnCall     *expvar.Map
	YandexS3          *expvar.Map
	YandexDataStreams *expvar.Map
	Syslog            *expvar.Map
	Cliq              *expvar.Map
	PolicyReport      *expvar.Map
	NodeRed           *expvar.Map
	MQTT              *expvar.Map
	Zincsearch        *expvar.Map
	Gotify            *expvar.Map
	Spyderbat         *expvar.Map
	TimescaleDB       *expvar.Map
	Redis             *expvar.Map
	Telegram          *expvar.Map
	N8N               *expvar.Map
	OpenObserve       *expvar.Map
	Dynatrace         *expvar.Map
	OTLPTraces        *expvar.Map
}

// PromStatistics is a struct to store prometheus metrics
type PromStatistics struct {
	Falco   *prometheus.CounterVec
	Inputs  *prometheus.CounterVec
	Outputs *prometheus.CounterVec
}
