package outputs

import (
	"cloud.google.com/go/pubsub"
	"context"
	"encoding/base64"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
	"log"
	"os"
	"errors"
	"encoding/json"
	"github.com/DataDog/datadog-go/statsd"
	"github.com/falcosecurity/falcosidekick/types"
)

// NewGCPClient returns a new output.Client for accessing the GCP API.
func NewGCPClient(config *types.Configuration, stats *types.Statistics, statsdClient, dogstatsdClient *statsd.Client) (*Client, error) {

	if config.GCP.Credentials != "" {
		os.Setenv("GCP_CREDENTIALS", config.GCP.Credentials)
		os.Setenv("GCP_PUBSUB_PROJECTID", config.GCP.PubSub.ProjectID)
		os.Setenv("GCP_PUBSUB_TOPIC", config.GCP.PubSub.Topic)
	}

	base64decodedCredentialsData, err := base64.StdEncoding.DecodeString(config.GCP.Credentials)
	if err != nil {
		log.Printf("[ERROR] : GCP - %v\n", "Error while base64-decoding GCP Credentials")
		return nil, errors.New("Error while base64-decoding GCP Credentials")
	}
	googleCredentialsData := string(base64decodedCredentialsData)
	var topicClient *pubsub.Topic

	if config.GCP.PubSub.ProjectID != "" && config.GCP.PubSub.Topic != "" {
		credentials, err := google.CredentialsFromJSON(context.Background(), []byte(googleCredentialsData), pubsub.ScopePubSub)
		if err != nil {
			log.Printf("[ERROR] : GCP PubSub - %v\n", "Error while loading GCP Credentials")
			return nil, errors.New("Error while loading GCP Credentials")
		}
		pubSubClient, err := pubsub.NewClient(context.Background(), config.GCP.PubSub.ProjectID, option.WithCredentials(credentials))
		if err != nil {
			log.Printf("[ERROR] : GCP PubSub - %v\n", "Error while creating GCP PubSub Client")
			return nil, errors.New("Error while creating GCP PubSub Client")
		}
		topicClient = pubSubClient.Topic(config.GCP.PubSub.Topic)
	}
	return &Client{
		OutputType:      "GCP",
		Config:          config,
		GCPTopicClient:  topicClient,
		Stats:           stats,
		StatsdClient:    statsdClient,
		DogstatsdClient: dogstatsdClient,
	}, nil
}

// GCPPublishTopic sends a message to a GCP PubSub Topic
func (c *Client) GCPPublishTopic(falcopayload types.FalcoPayload) {
	c.Stats.GCPPubSub.Add("total", 1)
	go c.CountMetric("outputs", 1, []string{"output:gcppubsub", "status:ok"})

	payload, _ := json.Marshal(falcopayload)
	message := &pubsub.Message{
		Data: payload,
	}
	result := c.GCPTopicClient.Publish(context.Background(), message)
	id, err := result.Get(context.Background())
	if err != nil {
  	log.Printf("[ERROR] : GCPPubSub - %v - %v\n", "Error while publishing message", err.Error())
		c.Stats.GCPPubSub.Add("error", 1)
		go c.CountMetric("outputs", 1, []string{"output:gcppubsub", "status:error"})
		return
	}
	log.Printf("[INFO]  : GCPPubSub - Send to topic OK (%v)\n", id)
  	c.Stats.GCPPubSub.Add("ok", 1)
		go c.CountMetric("outputs", 1, []string{"output:gcppubsub", "status:ok"})
}
