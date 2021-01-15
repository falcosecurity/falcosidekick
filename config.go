package main

import (
	"log"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"

	"github.com/falcosecurity/falcosidekick/types"

	"github.com/spf13/viper"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

func getConfig() *types.Configuration {
	c := &types.Configuration{
		Customfields: make(map[string]string),
		Webhook:      types.WebhookOutputConfig{CustomHeaders: make(map[string]string)},
		CloudEvents:  types.CloudEventsOutputConfig{Extensions: make(map[string]string)},
	}

	configFile := kingpin.Flag("config-file", "config file").Short('c').ExistingFile()
	kingpin.Parse()

	v := viper.New()
	v.SetDefault("ListenPort", 2801)
	v.SetDefault("Debug", false)
	v.SetDefault("CheckCert", true)
	v.SetDefault("Slack.WebhookURL", "")
	v.SetDefault("Slack.Footer", "https://github.com/falcosecurity/falcosidekick")
	v.SetDefault("Slack.Username", "Falcosidekick")
	v.SetDefault("Slack.Icon", "https://raw.githubusercontent.com/falcosecurity/falcosidekick/master/imgs/falcosidekick_color.png")
	v.SetDefault("Slack.OutputFormat", "all")
	v.SetDefault("Slack.MessageFormat", "")
	v.SetDefault("Slack.MinimumPriority", "")
	v.SetDefault("Rocketchat.WebhookURL", "")
	v.SetDefault("Rocketchat.Footer", "https://github.com/falcosecurity/falcosidekick")
	v.SetDefault("Rocketchat.Username", "Falcosidekick")
	v.SetDefault("Rocketchat.Icon", "https://raw.githubusercontent.com/falcosecurity/falcosidekick/master/imgs/falcosidekick_color.png")
	v.SetDefault("Rocketchat.OutputFormat", "all")
	v.SetDefault("Rocketchat.MessageFormat", "")
	v.SetDefault("Rocketchat.MinimumPriority", "")
	v.SetDefault("Mattermost.WebhookURL", "")
	v.SetDefault("Mattermost.Footer", "https://github.com/falcosecurity/falcosidekick")
	v.SetDefault("Mattermost.Username", "Falcosidekick")
	v.SetDefault("Mattermost.Icon", "https://raw.githubusercontent.com/falcosecurity/falcosidekick/master/imgs/falcosidekick_color.png")
	v.SetDefault("Mattermost.OutputFormat", "all")
	v.SetDefault("Mattermost.MessageFormat", "")
	v.SetDefault("Mattermost.MinimumPriority", "")
	v.SetDefault("Teams.WebhookURL", "")
	v.SetDefault("Teams.ActivityImage", "https://raw.githubusercontent.com/falcosecurity/falcosidekick/master/imgs/falcosidekick_color.png")
	v.SetDefault("Teams.OutputFormat", "all")
	v.SetDefault("Teams.MinimumPriority", "")
	v.SetDefault("Datadog.APIKey", "")
	v.SetDefault("Datadog.Host", "https://api.datadoghq.com")
	v.SetDefault("Datadog.MinimumPriority", "")
	v.SetDefault("Discord.WebhookURL", "")
	v.SetDefault("Discord.MinimumPriority", "")
	v.SetDefault("Discord.Icon", "https://raw.githubusercontent.com/falcosecurity/falcosidekick/master/imgs/falcosidekick_color.png")
	v.SetDefault("Alertmanager.HostPort", "")
	v.SetDefault("Alertmanager.MinimumPriority", "")
	v.SetDefault("Elasticsearch.HostPort", "")
	v.SetDefault("Elasticsearch.Index", "falco")
	v.SetDefault("Elasticsearch.Type", "event")
	v.SetDefault("Elasticsearch.MinimumPriority", "")
	v.SetDefault("Elasticsearch.Suffix", "daily")
	v.SetDefault("Influxdb.HostPort", "")
	v.SetDefault("Influxdb.Database", "falco")
	v.SetDefault("Influxdb.User", "")
	v.SetDefault("Influxdb.Password", "")
	v.SetDefault("Influxdb.MinimumPriority", "")
	v.SetDefault("Loki.HostPort", "")
	v.SetDefault("Loki.MinimumPriority", "")
	v.SetDefault("AWS.AccessKeyID", "")
	v.SetDefault("AWS.SecretAccessKey", "")
	v.SetDefault("AWS.Region", "")
	v.SetDefault("AWS.Lambda.FunctionName", "")
	v.SetDefault("AWS.Lambda.InvocationType", "RequestResponse")
	v.SetDefault("AWS.Lambda.Logtype", "Tail")
	v.SetDefault("AWS.Lambda.MinimumPriority", "")
	v.SetDefault("AWS.SQS.URL", "")
	v.SetDefault("AWS.SQS.MinimumPriority", "")
	v.SetDefault("AWS.SNS.TopicArn", "")
	v.SetDefault("AWS.SNS.MinimumPriority", "")
	v.SetDefault("AWS.SNS.RawJSON", false)
	v.SetDefault("AWS.CloudWatchLogs.LogGroup", "")
	v.SetDefault("AWS.CloudWatchLogs.LogStream", "")
	v.SetDefault("AWS.CloudWatchLogs.MinimumPriority", "")
	v.SetDefault("SMTP.HostPort", "")
	v.SetDefault("SMTP.User", "")
	v.SetDefault("SMTP.Password", "")
	v.SetDefault("SMTP.From", "")
	v.SetDefault("SMTP.To", "")
	v.SetDefault("SMTP.OutputFormat", "html")
	v.SetDefault("SMTP.MinimumPriority", "")
	v.SetDefault("STAN.HostPort", "")
	v.SetDefault("STAN.ClusterID", "")
	v.SetDefault("STAN.ClientID", "")
	v.SetDefault("NATS.HostPort", "")
	v.SetDefault("NATS.ClusterID", "")
	v.SetDefault("NATS.ClientID", "")
	v.SetDefault("Opsgenie.Region", "us")
	v.SetDefault("Opsgenie.APIKey", "")
	v.SetDefault("Opsgenie.MinimumPriority", "")
	v.SetDefault("Statsd.Forwarder", "")
	v.SetDefault("Statsd.Namespace", "falcosidekick.")
	v.SetDefault("Dogstatsd.Forwarder", "")
	v.SetDefault("Dogstatsd.Namespace", "falcosidekick.")
	v.SetDefault("Dogstatsd.Tags", []string{})
	v.SetDefault("Customfields", map[string]string{})
	v.SetDefault("Webhook.Address", "")
	v.SetDefault("Webhook.MinimumPriority", "")
	v.SetDefault("CloudEvents.Address", "")
	v.SetDefault("CloudEvents.MinimumPriority", "")
	v.SetDefault("Azure.eventHub.Namespace", "")
	v.SetDefault("Azure.eventHub.Name", "")
	v.SetDefault("Azure.eventHub.MinimumPriority", "")
	v.SetDefault("GCP.Credentials", "")
	v.SetDefault("GCP.PubSub.ProjectID", "")
	v.SetDefault("GCP.PubSub.Topic", "")
	v.SetDefault("GCP.PubSub.MinimumPriority", "")
	v.SetDefault("Googlechat.WebhookURL", "")
	v.SetDefault("Googlechat.OutputFormat", "all")
	v.SetDefault("Googlechat.MessageFormat", "")
	v.SetDefault("Googlechat.MinimumPriority", "")
	v.SetDefault("Kafka.URL", "")
	v.SetDefault("Kafka.Topic", "")
	v.SetDefault("Kafka.Partition", 0)
	v.SetDefault("Kafka.MinimumPriority", "")
	v.SetDefault("Pagerduty.APIKey", "")
	v.SetDefault("Pagerduty.Service", "")
	v.SetDefault("Pagerduty.Assignee", []string{})
	v.SetDefault("Pagerduty.EscalationPolicy", "")
	v.SetDefault("Pagerduty.MinimumPriority", "")
	v.SetDefault("Kubeless.Namespace", "")
	v.SetDefault("Kubeless.Function", "")
	v.SetDefault("Kubeless.Port", 8080)
	v.SetDefault("Kubeless.Kubeconfig", "")
	v.SetDefault("Kubeless.MinimumPriority", "")

	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
	if *configFile != "" {
		d, f := path.Split(*configFile)
		if d == "" {
			d = "."
		}
		v.SetConfigName(f[0 : len(f)-len(filepath.Ext(f))])
		v.AddConfigPath(d)
		err := v.ReadInConfig()
		if err != nil {
			log.Printf("[ERROR] : Error when reading config file : %v\n", err)
		}
	}

	v.GetStringMapString("customfields")
	v.GetStringMapString("Webhook.CustomHeaders")
	v.GetStringMapString("CloudEvents.Extensions")
	v.Unmarshal(c)

	if value, present := os.LookupEnv("CUSTOMFIELDS"); present {
		customfields := strings.Split(value, ",")
		for _, label := range customfields {
			tagkeys := strings.Split(label, ":")
			if len(tagkeys) == 2 {
				c.Customfields[tagkeys[0]] = tagkeys[1]
			}
		}
	}

	if value, present := os.LookupEnv("WEBHOOK_CUSTOMHEADERS"); present {
		customfields := strings.Split(value, ",")
		for _, label := range customfields {
			tagkeys := strings.Split(label, ":")
			if len(tagkeys) == 2 {
				c.Webhook.CustomHeaders[tagkeys[0]] = tagkeys[1]
			}
		}
	}

	if value, present := os.LookupEnv("CLOUDEVENTS_EXTENSIONS"); present {
		customfields := strings.Split(value, ",")
		for _, label := range customfields {
			tagkeys := strings.Split(label, ":")
			if len(tagkeys) == 2 {
				c.CloudEvents.Extensions[tagkeys[0]] = tagkeys[1]
			}
		}
	}

	if c.ListenPort == 0 || c.ListenPort > 65536 {
		log.Fatalf("[ERROR] : Bad port number\n")
	}

	c.Slack.MinimumPriority = checkPriority(c.Slack.MinimumPriority)
	c.Rocketchat.MinimumPriority = checkPriority(c.Rocketchat.MinimumPriority)
	c.Mattermost.MinimumPriority = checkPriority(c.Mattermost.MinimumPriority)
	c.Teams.MinimumPriority = checkPriority(c.Teams.MinimumPriority)
	c.Datadog.MinimumPriority = checkPriority(c.Datadog.MinimumPriority)
	c.Alertmanager.MinimumPriority = checkPriority(c.Alertmanager.MinimumPriority)
	c.Elasticsearch.MinimumPriority = checkPriority(c.Elasticsearch.MinimumPriority)
	c.Influxdb.MinimumPriority = checkPriority(c.Influxdb.MinimumPriority)
	c.Loki.MinimumPriority = checkPriority(c.Loki.MinimumPriority)
	c.Nats.MinimumPriority = checkPriority(c.Nats.MinimumPriority)
	c.Stan.MinimumPriority = checkPriority(c.Stan.MinimumPriority)
	c.AWS.Lambda.MinimumPriority = checkPriority(c.AWS.Lambda.MinimumPriority)
	c.AWS.SQS.MinimumPriority = checkPriority(c.AWS.SQS.MinimumPriority)
	c.AWS.SNS.MinimumPriority = checkPriority(c.AWS.SNS.MinimumPriority)
	c.AWS.CloudWatchLogs.MinimumPriority = checkPriority(c.AWS.CloudWatchLogs.MinimumPriority)
	c.Opsgenie.MinimumPriority = checkPriority(c.Opsgenie.MinimumPriority)
	c.Webhook.MinimumPriority = checkPriority(c.Webhook.MinimumPriority)
	c.CloudEvents.MinimumPriority = checkPriority(c.CloudEvents.MinimumPriority)
	c.Azure.EventHub.MinimumPriority = checkPriority(c.Azure.EventHub.MinimumPriority)
	c.GCP.PubSub.MinimumPriority = checkPriority(c.GCP.PubSub.MinimumPriority)
	c.Googlechat.MinimumPriority = checkPriority(c.Googlechat.MinimumPriority)
	c.Kafka.MinimumPriority = checkPriority(c.Kafka.MinimumPriority)
	c.Pagerduty.MinimumPriority = checkPriority(c.Pagerduty.MinimumPriority)
	c.Kubeless.MinimumPriority = checkPriority(c.Kubeless.MinimumPriority)

	c.Slack.MessageFormatTemplate = getMessageFormatTemplate("Slack", c.Slack.MessageFormat)
	c.Rocketchat.MessageFormatTemplate = getMessageFormatTemplate("Rocketchat", c.Rocketchat.MessageFormat)
	c.Mattermost.MessageFormatTemplate = getMessageFormatTemplate("Mattermost", c.Mattermost.MessageFormat)
	c.Googlechat.MessageFormatTemplate = getMessageFormatTemplate("Googlechat", c.Googlechat.MessageFormat)
	return c
}

func checkPriority(prio string) string {
	match, _ := regexp.MatchString("(?i)(emergency|alert|critical|error|warning|notice|informational|debug)", prio)
	if match {
		return prio
	}

	return ""
}

func getMessageFormatTemplate(output, temp string) *template.Template {
	if temp != "" {
		var err error
		t, err := template.New(output).Parse(temp)
		if err != nil {
			log.Fatalf("[ERROR] : Error compiling %v message template : %v\n", output, err)
		}
		return t
	}

	return nil
}
