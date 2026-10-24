// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/syslog"
	"net"
	"os"
	"strings"
	"time"

	"github.com/DataDog/datadog-go/statsd"
	"go.opentelemetry.io/otel/attribute"

	"github.com/falcosecurity/falcosidekick/internal/pkg/utils"
	otlpmetrics "github.com/falcosecurity/falcosidekick/outputs/otlp_metrics"
	"github.com/falcosecurity/falcosidekick/types"
)

func NewSyslogClient(config *types.Configuration, stats *types.Statistics, promStats *types.PromStatistics,
	otlpMetrics *otlpmetrics.OTLPMetrics, statsdClient, dogstatsdClient *statsd.Client) (*Client, error) {
	ok := isValidProtocolString(strings.ToLower(config.Syslog.Protocol))
	if !ok {
		return nil, fmt.Errorf("failed to configure Syslog client: invalid protocol %s", config.Syslog.Protocol)
	}
	if config.Syslog.TLS && strings.ToLower(config.Syslog.Protocol) != TCP {
		return nil, fmt.Errorf("failed to configure Syslog client: TLS requires the %s protocol, got %s", TCP, config.Syslog.Protocol)
	}

	return &Client{
		OutputType:      "Syslog",
		Config:          config,
		Stats:           stats,
		PromStats:       promStats,
		OTLPMetrics:     otlpMetrics,
		StatsdClient:    statsdClient,
		DogstatsdClient: dogstatsdClient,
	}, nil
}

func isValidProtocolString(protocol string) bool {
	return protocol == TCP || protocol == UDP
}

const syslogTLSDialTimeout = 10 * time.Second

// syslogTLSConfig builds the TLS configuration used to reach the syslog server.
func (c *Client) syslogTLSConfig() (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}

	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	cfg.RootCAs = pool

	if c.Config.TLSClient.CaCertFile != "" {
		caCert, err := os.ReadFile(c.Config.TLSClient.CaCertFile)
		if err != nil {
			return nil, err
		}
		pool.AppendCertsFromPEM(caCert)
	}

	if c.Config.Syslog.MutualTLS {
		certPath, keyPath, caPath := c.Config.MutualTLSClient.CertFile, c.Config.MutualTLSClient.KeyFile, c.Config.MutualTLSClient.CaCertFile
		if certPath == "" {
			certPath = c.Config.MutualTLSFilesPath + MutualTLSClientCertFilename
		}
		if keyPath == "" {
			keyPath = c.Config.MutualTLSFilesPath + MutualTLSClientKeyFilename
		}
		if caPath == "" {
			caPath = c.Config.MutualTLSFilesPath + MutualTLSCacertFilename
		}
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, err
		}
		caCert, err := os.ReadFile(caPath)
		if err != nil {
			return nil, err
		}
		pool.AppendCertsFromPEM(caCert)
		cfg.Certificates = []tls.Certificate{cert}
		return cfg, nil
	}

	// With MutualTLS enabled, the check cert flag is ignored
	if !c.Config.Syslog.CheckCert {
		return utils.InsecureSkipVerifyTLSConfig(), nil
	}
	return cfg, nil
}

// sendSyslogTLS writes one message to the syslog server over TLS, as an RFC 5424
// message with the octet-counting framing of RFC 5425.
func (c *Client) sendSyslogTLS(endpoint string, priority syslog.Priority, hostname string, payload []byte) error {
	cfg, err := c.syslogTLSConfig()
	if err != nil {
		return err
	}
	dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: syslogTLSDialTimeout}, Config: cfg}
	conn, err := dialer.Dial("tcp", endpoint)
	if err != nil {
		return err
	}
	defer conn.Close()

	_, err = io.WriteString(conn, formatSyslogTLSFrame(priority, time.Now(), hostname, payload))
	return err
}

// formatSyslogTLSFrame returns an RFC 5424 message prefixed by its length (RFC 5425 section 4.3).
func formatSyslogTLSFrame(priority syslog.Priority, ts time.Time, hostname string, payload []byte) string {
	if hostname == "" {
		hostname = "-"
	}
	msg := fmt.Sprintf("<%d>1 %s %s %s - - - %s", int(priority), ts.Format(time.RFC3339), hostname, Falco, payload)
	return fmt.Sprintf("%d %s", len(msg), msg)
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

	var err error
	if c.Config.Syslog.TLS {
		hostname, _ := os.Hostname()
		err = c.sendSyslogTLS(endpoint, priority, hostname, payload)
	} else {
		var sysLog *syslog.Writer
		sysLog, err = syslog.Dial(c.Config.Syslog.Protocol, endpoint, priority, Falco)
		if err == nil {
			defer sysLog.Close()
			_, err = sysLog.Write(payload)
		}
	}
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:syslog", "status:error"})
		c.Stats.Syslog.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "syslog", "status": Error}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "syslog"),
			attribute.String("status", Error)).Inc()
		utils.Log(utils.ErrorLvl, c.OutputType, err.Error())
		return
	}

	go c.CountMetric(Outputs, 1, []string{"output:syslog", "status:ok"})
	c.Stats.Syslog.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "syslog", "status": OK}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "syslog"), attribute.String("status", OK)).Inc()
}
