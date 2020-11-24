package outputs

import (
	"encoding/json"
	"log"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/falcosecurity/falcosidekick/types"
	"gopkg.in/confluentinc/confluent-kafka-go.v1/kafka"
)

// NewKafkaClient returns a new output.Client for accessing the Apache Kafka.
func NewKafkaClient(config *types.Configuration, stats *types.Statistics, promStats *types.PromStatistics, statsdClient, dogstatsdClient *statsd.Client) (*Client, error) {
	p, err := kafka.NewProducer(&kafka.ConfigMap{"bootstrap.servers": config.Kafka.URL})
	if err != nil {
		log.Printf("[ERROR] : Kafka - %v\n", "Error connecting Apache Kafka server")
		return nil, err
	}

	return &Client{
		OutputType:      "Kafka",
		Config:          config,
		Stats:           stats,
		PromStats:       promStats,
		StatsdClient:    statsdClient,
		DogstatsdClient: dogstatsdClient,
		KafkaProducer:   p,
	}, nil
}

// KafkaProduce sends a message to a Apach Kafka Topic
func (c *Client) KafkaProduce(falcopayload types.FalcoPayload) {
	b, err := json.Marshal(falcopayload)
	if err != nil {
		log.Printf("[ERROR] : Kafka - %v - %v\n", "Error while marshalling message", err.Error())
	}

	msg := &kafka.Message{
		TopicPartition: kafka.TopicPartition{
			Topic: &c.Config.Kafka.Topic,
		},
		Value: b,
	}

	if c.Config.Kafka.Partition == 0 {
		msg.TopicPartition.Partition = kafka.PartitionAny
	} else {
		msg.TopicPartition.Partition = c.Config.Kafka.Partition
	}

	err = c.KafkaProducer.Produce(msg, nil)

	if err != nil {
		c.Stats.Kafka.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "kafka", "status": Error}).Inc()
	} else {
		c.Stats.Kafka.Add(OK, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "kafka", "status": OK}).Inc()
	}
	c.Stats.Kafka.Add(Total, 1)
}
