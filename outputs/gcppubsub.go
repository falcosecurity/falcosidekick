package outputs

import (
	"cloud.google.com/go/pubsub"
	"context"
	"encoding/base64"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
	"log"
	"os"
	"time"
	"errors"
	"encoding/json"
	"github.com/DataDog/datadog-go/statsd"
	"github.com/falcosecurity/falcosidekick/types"
)

// NewGCPClient returns a new output.Client for accessing the GCP API.
func NewGCPPubSubClient(config *types.Configuration, stats *types.Statistics, statsdClient, dogstatsdClient *statsd.Client) (*Client, error) {

	if config.GCPPubSub.ProjectID != "" && config.GCPPubSub.Topic != "" && config.GCPPubSub.Credentials != "" {
		os.Setenv("GCPPUBSUB_PROJECTID", config.GCPPubSub.ProjectID)
		os.Setenv("GCPPUBSUB_TOPIC", config.GCPPubSub.Topic)
		os.Setenv("GCPPUBSUB_CREDENTIALS", config.GCPPubSub.Credentials)
	}

	base64decodedCredentialsData, err := base64.StdEncoding.DecodeString(config.GCPPubSub.Credentials)
	if err != nil {
		log.Printf("[ERROR] : GCPPubSub - %v\n", "Error while base64-decoding GCP Credentials")
		return nil, errors.New("Error while base64-decoding GCP Credentials") 
	}

	googleCredentialsData := string(base64decodedCredentialsData)
	credentials, err := google.CredentialsFromJSON(context.Background(), []byte(googleCredentialsData), pubsub.ScopePubSub)
	if err != nil {
		log.Printf("[ERROR] : GCPPubSub - %v\n", "Error while loading GCP Credentials")
		return nil, errors.New("Error while loading GCP Credentials")
	}

	pubSubClient, err := pubsub.NewClient(context.Background(), config.GCPPubSub.ProjectID, option.WithCredentials(credentials))
	if err != nil {
                log.Printf("[ERROR] : GCPPubSub - %v\n", "Error while creating GCP PubSub Client")
                return nil, errors.New("Error while creating GCP PubSub Client")
	}
	//defer pubSubClient.Close()

	return &Client{
		OutputType:      "GCPPubSub",
		Config:          config,
		GCPPubSubClient: pubSubClient,
		Stats:           stats,
		StatsdClient:    statsdClient,
		DogstatsdClient: dogstatsdClient,
	}, nil
}

// PublishTopic sends a message to a PubSub Topic
func (c *Client) GCPPublishTopic(falcopayload types.FalcoPayload) {

	c.Stats.GCPPubSub.Add("total", 1)
	go c.CountMetric("outputs", 1, []string{"output:gcppubsub", "status:ok"})

	topic := c.GCPPubSubClient.Topic(c.Config.GCPPubSub.Topic)
	defer topic.Stop()
	
	payload, _ := json.Marshal(falcopayload)
	message := &pubsub.Message{
		Data: payload,
	}

	ctxPublish, cancelPublish := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelPublish()

	result := topic.Publish(ctxPublish, message)

	ctxGet, cancelGet := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelGet()

	id, err := result.Get(ctxGet)
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
