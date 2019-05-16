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
	v.SetDefault("Listen_Port", 2801)
	v.SetDefault("Slack_Output_Format", "all")

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

	if c.Listen_Port == 0 || c.Listen_Port > 65536 {
		log.Fatalf("[ERROR] : Bad port number\n")
	}

	return c
}
