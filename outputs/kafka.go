package outputs

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/segmentio/kafka-go"

	"github.com/falcosecurity/falcosidekick/types"
)

// NewKafkaClient returns a new output.Client for accessing the Apache Kafka.
func NewKafkaClient(config *types.Configuration, stats *types.Statistics, promStats *types.PromStatistics, statsdClient, dogstatsdClient *statsd.Client) (*Client, error) {
	conn, err := kafka.DialLeader(context.Background(), "tcp", config.Kafka.HostPort, config.Kafka.Topic, config.Kafka.Partition)
	if err != nil {
		log.Printf("[ERROR] : Kafka - %v - %v\n", "failed to connect to Apache Kafka server", err.Error())
		return nil, err
	}

	return &Client{
		OutputType:      "Kafka",
		Config:          config,
		Stats:           stats,
		PromStats:       promStats,
		StatsdClient:    statsdClient,
		DogstatsdClient: dogstatsdClient,
		KafkaProducer:   conn,
	}, nil
}

// KafkaProduce sends a message to a Apach Kafka Topic
func (c *Client) KafkaProduce(falcopayload types.FalcoPayload) {
	c.Stats.Kafka.Add(Total, 1)

	falcoMsg, err := json.Marshal(falcopayload)
	if err != nil {
		c.setKafkaErrorMetrics()
		log.Printf("[ERROR] : Kafka - %v - %v\n", "failed to marshalling message", err.Error())
		return
	}

	kafkaMsg := kafka.Message{
		Value: falcoMsg,
	}

	c.KafkaProducer.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err = c.KafkaProducer.WriteMessages(kafkaMsg)
	if err != nil {
		c.setKafkaErrorMetrics()
		log.Printf("[ERROR] : Kafka - %v\n", err)
		return
	}

	go c.CountMetric("outputs", 1, []string{"output:kafka", "status:ok"})
	c.Stats.Kafka.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "kafka", "status": OK}).Inc()
	log.Printf("[INFO] : Kafka - Publish OK\n")
}

// setKafkaErrorMetrics set the error stats
func (c *Client) setKafkaErrorMetrics() {
	go c.CountMetric(Outputs, 1, []string{"output:kafka", "status:error"})
	c.Stats.Kafka.Add(Error, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "kafka", "status": Error}).Inc()
}
