// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/falcosecurity/falcosidekick/types"
	"github.com/telkomdev/go-stash"
)

/*
Logstash throws a jsonparse error if keys contain an index, e.g., "key[0]".
This function is meant to get rid of the index brackets format in favor of dots.
For the previous example, the "key[0]" value will be replaced by "key.0".
*/
func replaceKeysWithIndexes(data map[string]interface{}) map[string]interface{} {
	newData := make(map[string]interface{})
	re := regexp.MustCompile(`\[(\d+)\]`)

	for key, value := range data {
		newKey := re.ReplaceAllStringFunc(key, func(match string) string {
			return "." + re.FindStringSubmatch(match)[1]
		})

		// Recursively process nested maps
		if nestedMap, ok := value.(map[string]interface{}); ok {
			newData[newKey] = replaceKeysWithIndexes(nestedMap)
		} else {
			newData[newKey] = value
		}
	}
	return newData
}

func firstValid(paths []string) string {
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}

func NewLogstashClient(config *types.Configuration, stats *types.Statistics, promStats *types.PromStatistics,
	statsdClient, dogstatsdClient *statsd.Client) (*Client, error) {
	var tlsCfg *tls.Config

	if mTLS := config.Logstash.MutualTLS; mTLS {
		// Get certificates
		var MutualTLSClientCertPath, MutualTLSClientKeyPath, MutualTLSClientCaCertPath string

		MutualTLSClientCertPath = firstValid([]string{config.Logstash.CertFile, config.MutualTLSClient.CertFile, config.MutualTLSFilesPath + "/client.crt"})
		MutualTLSClientKeyPath = firstValid([]string{config.Logstash.KeyFile, config.MutualTLSClient.KeyFile, config.MutualTLSFilesPath + "/client.key"})
		MutualTLSClientCaCertPath = firstValid([]string{config.Logstash.CaCertFile, config.MutualTLSClient.CaCertFile, config.MutualTLSFilesPath + "/ca.crt"})

		cert, err := tls.LoadX509KeyPair(MutualTLSClientCertPath, MutualTLSClientKeyPath)
		if err != nil {
			log.Printf("[ERROR] : Logstash - Failed to load SSL certificate: %v\n", err)
		}

		caCert, err := os.ReadFile(MutualTLSClientCaCertPath)
		if err != nil {
			log.Printf("[ERROR] : Logstash - Failed to load SSL CA certificate: %v\n", err)
		}

		// Configure TLS

		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}

		tlsCfg = &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{cert},
			RootCAs:      pool,
		}
		tlsCfg.RootCAs.AppendCertsFromPEM(caCert)

	} else {
		// The check cert flag and mutual tls are mutually exclusive
		if !config.Logstash.CheckCert {
			tlsCfg = &tls.Config{
				InsecureSkipVerify: true, // #nosec G402 This is only set as a result of explicit configuration
			}
		}
	}

	lClient, err := stash.Connect(config.Logstash.Address, config.Logstash.Port, stash.SetTLSConfig(tlsCfg), stash.SetTLS(config.Logstash.TLS || config.Logstash.MutualTLS))

	if err != nil {
		log.Printf("[ERROR] : Logstash - Misconfiguration, cannot connect to the server: %v\n", err)
	}
	log.Printf("[INFO] : Logstash - Connected to logstash server\n")

	return &Client{
		OutputType:      "Logstash",
		Config:          config,
		LogstashClient:  lClient,
		Stats:           stats,
		PromStats:       promStats,
		StatsdClient:    statsdClient,
		DogstatsdClient: dogstatsdClient,
	}, nil
}

func (c *Client) LogstashPost(falcopayload types.FalcoPayload) {
	status := OK
	loglevel := "INFO"
	c.Stats.Logstash.Add(Total, 1)

	falcopayload.OutputFields = replaceKeysWithIndexes(falcopayload.OutputFields)

	falcopayload.Tags = append(falcopayload.Tags, c.Config.Logstash.Tags...)
	logstashPayload, _ := json.Marshal(falcopayload)

	n, err := c.LogstashClient.Write(logstashPayload)
	if err != nil {
		status = Error
		loglevel = strings.ToUpper(status)
	}

	c.Stats.Logstash.Add(status, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "logstash", "status": status}).Inc()
	go c.CountMetric(Outputs, 1, []string{"output:logstash", fmt.Sprintf("status:%v", status)})

	log.Printf("[%v] : output.logstash status=%v (%v)\n", loglevel, status, n)
}
