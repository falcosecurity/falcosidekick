// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"encoding/json"
	"fmt"
	"log"
	"log/syslog"
	"strings"
	"time"

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

func getCEFSeverity(priority types.PriorityType) string {
	switch priority {
	case types.Debug:
		return "0"
	case types.Informational:
		return "3"
	case types.Notice:
		return "4"
	case types.Warning:
		return "6"
	case types.Error:
		return "7"
	case types.Critical:
		return "8"
	case types.Alert:
		return "9"
	case types.Emergency:
		return "10"
	default:
		return "Uknown"
	}
}

func (c *Client) SyslogPost(falcopayload types.FalcoPayload) {
	c.Stats.Syslog.Add(Total, 1)
	endpoint := fmt.Sprintf("%s:%s", c.Config.Syslog.Host, c.Config.Syslog.Port)

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

	var payload []byte

	if c.Config.Syslog.Format == "cef" {
		s := fmt.Sprintf(
			"CEF:0|Falcosecurity|Falco|1.0|Falco Event|%v|%v|uuid=%v start=%v msg=%v source=%v",
			falcopayload.Rule,
			getCEFSeverity(falcopayload.Priority),
			falcopayload.UUID,
			falcopayload.Time.Format(time.RFC3339),
			falcopayload.Output,
			falcopayload.Source,
		)
		if falcopayload.Hostname != "" {
			s += " hostname=" + falcopayload.Hostname
		}
		s += " outputfields="
		for i, j := range falcopayload.OutputFields {
			s += fmt.Sprintf("%v:%v ", i, j)
		}
		if len(falcopayload.Tags) != 0 {
			s += "tags=" + strings.Join(falcopayload.Tags, ",")
		}
		payload = []byte(strings.TrimSuffix(s, " "))
	} else {
		payload, _ = json.Marshal(falcopayload)
	}

	_, err = sysLog.Write(payload)
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
