// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/sasl/plain"
	"github.com/segmentio/kafka-go/sasl/scram"

	"github.com/falcosecurity/falcosidekick/types"
)

// NewKafkaClient returns a new output.Client for accessing the Apache Kafka.
func NewKafkaClient(config *types.Configuration, stats *types.Statistics, promStats *types.PromStatistics, statsdClient, dogstatsdClient *statsd.Client) (*Client, error) {

	transport := &kafka.Transport{
		Dial: (&net.Dialer{
			Timeout:   3 * time.Second,
			DualStack: true,
		}).DialContext,
		ClientID: config.Kafka.ClientID,
	}

	if config.Kafka.TLS {
		caCertPool, err := x509.SystemCertPool()

		if err != nil {
			log.Printf("[ERROR] : Kafka - failed to initialize root CAs: %v", err)
		}

		transport.TLS = &tls.Config{
			RootCAs:    caCertPool,
			MinVersion: tls.VersionTLS12,
		}
	}

	var err error

	if config.Kafka.SASL != "" {
		saslMode := strings.ToUpper(config.Kafka.SASL)
		switch {
		case saslMode == "PLAIN":
			transport.SASL = plain.Mechanism{
				Username: config.Kafka.Username,
				Password: config.Kafka.Password,
			}
		case strings.HasPrefix(saslMode, "SCRAM_"):
			algo := strings.TrimPrefix(config.Kafka.SASL, "SCRAM_")
			switch algo {
			case "SHA256":
				transport.SASL, err = scram.Mechanism(scram.SHA256, config.Kafka.Username, config.Kafka.Password)
			case "SHA512":
				transport.SASL, err = scram.Mechanism(scram.SHA512, config.Kafka.Username, config.Kafka.Password)
			default:
				err = fmt.Errorf("unsupported SASL SCRAM algorithm %q", algo)
			}
			if err != nil {
				err = fmt.Errorf("failed to initialize SASL SCRAM %q: %w", algo, err)
			}
		default:
			err = fmt.Errorf("unsupported SASL mode: %q", config.Kafka.SASL)
		}
	}
	if err != nil {
		log.Printf("[ERROR] : Kafka - %v\n", err)
		return nil, err
	}

	kafkaWriter := &kafka.Writer{
		Addr:                   kafka.TCP(strings.Split(config.Kafka.HostPort, ",")...),
		Topic:                  config.Kafka.Topic,
		Async:                  config.Kafka.Async,
		Transport:              transport,
		AllowAutoTopicCreation: config.Kafka.TopicCreation,
	}

	switch strings.ToLower(config.Kafka.Balancer) {
	case "crc32":
		kafkaWriter.Balancer = kafka.CRC32Balancer{Consistent: true}
	case "crc32_random":
		kafkaWriter.Balancer = kafka.CRC32Balancer{Consistent: false}
	case "murmur2":
		kafkaWriter.Balancer = kafka.Murmur2Balancer{Consistent: true}
	case "murmur2_random":
		kafkaWriter.Balancer = kafka.Murmur2Balancer{Consistent: false}
	case "least_bytes":
		kafkaWriter.Balancer = &kafka.LeastBytes{}
	case "round_robin":
		kafkaWriter.Balancer = &kafka.RoundRobin{}
	default:
		log.Printf("[ERROR] : Kafka - unsupported balancer %q\n", config.Kafka.Balancer)
		return nil, fmt.Errorf("unsupported balancer %q", config.Kafka.Balancer)
	}

	switch strings.ToUpper(config.Kafka.Compression) {
	case "GZIP":
		kafkaWriter.Compression = kafka.Gzip
	case "SNAPPY":
		kafkaWriter.Compression = kafka.Snappy
	case "LZ4":
		kafkaWriter.Compression = kafka.Lz4
	case "ZSTD":
		kafkaWriter.Compression = kafka.Zstd
	case "NONE":
		// leave as default, none
	default:
		log.Printf("[ERROR] : Kafka - unsupported compression %q\n", config.Kafka.Compression)
		return nil, fmt.Errorf("unsupported compression %q", config.Kafka.Compression)
	}

	switch strings.ToUpper(config.Kafka.RequiredACKs) {
	case "ALL":
		kafkaWriter.RequiredAcks = kafka.RequireAll
	case "ONE":
		kafkaWriter.RequiredAcks = kafka.RequireOne
	case "NONE":
		kafkaWriter.RequiredAcks = kafka.RequireNone
	default:
		log.Printf("[ERROR] : Kafka - unsupported required ACKs %q\n", config.Kafka.RequiredACKs)
		return nil, fmt.Errorf("unsupported required ACKs %q", config.Kafka.RequiredACKs)
	}

	client := &Client{
		OutputType:      "Kafka",
		Config:          config,
		Stats:           stats,
		PromStats:       promStats,
		StatsdClient:    statsdClient,
		DogstatsdClient: dogstatsdClient,
		KafkaProducer:   kafkaWriter,
	}
	kafkaWriter.Completion = client.handleKafkaCompletion
	return client, nil
}

// KafkaProduce sends a message to a Apach Kafka Topic
func (c *Client) KafkaProduce(falcopayload types.FalcoPayload) {
	c.Stats.Kafka.Add(Total, 1)

	falcoMsg, err := json.Marshal(falcopayload)
	if err != nil {
		c.incrKafkaErrorMetrics(1)
		log.Printf("[ERROR] : Kafka - %v - %v\n", "failed to marshalling message", err.Error())
		return
	}

	kafkaMsg := kafka.Message{
		Value: falcoMsg,
	}

	// Errors are logged/captured via handleKafkaCompletion function, ignore here
	err = c.KafkaProducer.WriteMessages(context.Background(), kafkaMsg)
	if err != nil {
		c.incrKafkaErrorMetrics(1)
		log.Printf("[ERROR] : Kafka - %v\n", err.Error())
		return
	} else {
		c.incrKafkaSuccessMetrics(1)
		log.Printf("[INFO]  : Kafka - Publish OK\n")
	}
}

// handleKafkaCompletion is called when a message is produced
func (c *Client) handleKafkaCompletion(messages []kafka.Message, err error) {
	if err != nil {
		c.incrKafkaErrorMetrics(len(messages))
		log.Printf("[ERROR] : Kafka (%d) - %v\n", len(messages), err)
	} else {
		c.incrKafkaSuccessMetrics(len(messages))
		log.Printf("[INFO]  : Kafka (%d) - Publish OK\n", len(messages))
	}
}

// incrKafkaSuccessMetrics increments the error stats
func (c *Client) incrKafkaSuccessMetrics(add int) {
	go c.CountMetric("outputs", int64(add), []string{"output:kafka", "status:ok"})
	c.Stats.Kafka.Add(OK, int64(add))
	c.PromStats.Outputs.With(map[string]string{"destination": "kafka", "status": OK}).Add(float64(add))
}

// incrKafkaErrorMetrics increments the error stats
func (c *Client) incrKafkaErrorMetrics(add int) {
	go c.CountMetric(Outputs, int64(add), []string{"output:kafka", "status:error"})
	c.Stats.Kafka.Add(Error, int64(add))
	c.PromStats.Outputs.With(map[string]string{"destination": "kafka", "status": Error}).Add(float64(add))
}
