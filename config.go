package main

import (
	"log"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/falcosecurity/falcosidekick/types"

	"github.com/spf13/viper"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

func getConfig() *types.Configuration {
	c := &types.Configuration{Customfields: make(map[string]string)}

	configFile := kingpin.Flag("config-file", "config file").Short('c').ExistingFile()
	kingpin.Parse()

	v := viper.New()
	v.SetDefault("ListenPort", 2801)
	v.SetDefault("Debug", false)
	v.SetDefault("Slack.WebhookURL", "")
	v.SetDefault("Slack.Footer", "https://github.com/falcosecurity/falcosidekick")
	v.SetDefault("Slack.Icon", "https://raw.githubusercontent.com/falcosecurity/falcosidekick/master/imgs/falcosidekick.png")
	v.SetDefault("Slack.OutputFormat", "all")
	v.SetDefault("Slack.MinimumPriority", "")
	v.SetDefault("Teams.WebhookURL", "")
	v.SetDefault("Teams.ActivityImage", "https://raw.githubusercontent.com/falcosecurity/falcosidekick/master/imgs/falcosidekick.png")
	v.SetDefault("Teams.OutputFormat", "all")
	v.SetDefault("Teams.MinimumPriority", "")
	v.SetDefault("Datadog.APIKey", "")
	v.SetDefault("Datadog.MinimumPriority", "")
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
	v.SetDefault("SMTP.HostPort", "")
	v.SetDefault("SMTP.User", "")
	v.SetDefault("SMTP.Password", "")
	v.SetDefault("SMTP.From", "")
	v.SetDefault("SMTP.To", "")
	v.SetDefault("SMTP.OutputFormat", "html")
	v.SetDefault("SMTP.MinimumPriority", "")
	v.SetDefault("AWS.SQS.MinimumPriority", "")
	v.SetDefault("Customfields", map[string]string{})

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

	if c.ListenPort == 0 || c.ListenPort > 65536 {
		log.Fatalf("[ERROR] : Bad port number\n")
	}
	if match, _ := regexp.MatchString("(?i)(emergency|alert|critical|error|warning|notice|informationnal|debug)", c.Slack.MinimumPriority); !match {
		c.Slack.MinimumPriority = ""
	}

	return c
}
