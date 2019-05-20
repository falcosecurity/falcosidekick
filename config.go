package main

import (
	"log"
	"path"
	"path/filepath"
	"strings"

	"github.com/Issif/falcosidekick/types"

	"github.com/spf13/viper"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

func getConfig() *types.Configuration {
	c := &types.Configuration{}

	configFile := kingpin.Flag("config-file", "config file").Short('c').ExistingFile()
	kingpin.Parse()

	v := viper.New()
	v.SetDefault("ListenPort", 2801)
	v.SetDefault("Debug", false)
	v.SetDefault("Slack.WebhookURL", "")
	v.SetDefault("Slack.Footer", "https://github.com/Issif/falcosidekick")
	v.SetDefault("Slack.Icon", "https://raw.githubusercontent.com/Issif/falcosidekick/master/imgs/falcosidekick.png")
	v.SetDefault("SlackOutput.OutputFormat", "all")
	v.SetDefault("Datadog.APIKey", "")
	v.SetDefault("Alertmanager.HostPort", "")
	v.SetDefault("Elasticsearch.HostPort", "")
	v.SetDefault("Elasticsearch.Index", "falco")
	v.SetDefault("Elasticsearch.Type", "event")

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
			log.Printf("Error when reading config file: %v\n", err)
		}
	}
	v.Unmarshal(c)

	if c.ListenPort == 0 || c.ListenPort > 65536 {
		log.Fatalf("[ERROR] : Bad port number\n")
	}

	return c
}
