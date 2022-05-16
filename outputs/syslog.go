package outputs

import (
	"encoding/json"
	"fmt"
	"log"
	"log/syslog"
	"strings"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/falcosecurity/falcosidekick/types"
)

func NewSyslogClient(config *types.Configuration, stats *types.Statistics, promStats *types.PromStatistics, statsdClient, dogstatsdClient *statsd.Client) (*Client, error) {
	ok := isValidProtocolString(strings.ToLower(config.Syslog.Protocol))
	if !ok {
		return nil, fmt.Errorf("failed to configure Syslog client: invalid protocol %s", config.Syslog.Protocol)
	}

	return &Client{
		OutputType:      "Syslog",
		Config:          config,
		Stats:           stats,
		PromStats:       promStats,
		StatsdClient:    statsdClient,
		DogstatsdClient: dogstatsdClient,
	}, nil
}

func isValidProtocolString(protocol string) bool {
	return protocol == TCP || protocol == UDP
}

func (c *Client) SyslogPost(falcopayload types.FalcoPayload) {
	c.Stats.Syslog.Add(Total, 1)
	endpoint := fmt.Sprintf("%s:%s", c.Config.Syslog.Host, c.Config.Syslog.Port)

	falcopayload.OutputFields["clustername"] = c.Config.Syslog.ClusterName

	var priority syslog.Priority
	switch falcopayload.Priority {
	case types.Emergency:
		priority = syslog.LOG_EMERG
	case types.Alert:
		priority = syslog.LOG_ALERT
	case types.Critical:
		priority = syslog.LOG_CRIT
	case types.Error:
		priority = syslog.LOG_ERR
	case types.Warning:
		priority = syslog.LOG_WARNING
	case types.Notice:
		priority = syslog.LOG_NOTICE
	case types.Informational:
		priority = syslog.LOG_INFO
	case types.Debug:
		priority = syslog.LOG_DEBUG
	}

	sysLog, err := syslog.Dial(c.Config.Syslog.Protocol, endpoint, priority, Falco)
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:syslog", "status:error"})
		c.Stats.Syslog.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "syslog", "status": Error}).Inc()
		log.Printf("[ERROR] : Syslog - %v\n", err)
		return
	}

	b, _ := json.Marshal(falcopayload)
	_, err = sysLog.Write(b)
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:syslog", "status:error"})
		c.Stats.Syslog.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "syslog", "status": Error}).Inc()
		log.Printf("[ERROR] : Syslog - %v\n", err)
		return
	}

	go c.CountMetric(Outputs, 1, []string{"output:syslog", "status:ok"})
	c.Stats.Syslog.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "syslog", "status": OK}).Inc()
}
