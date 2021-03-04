package outputs

import (
	"cloud.google.com/go/storage"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"cloud.google.com/go/pubsub"
	"github.com/DataDog/datadog-go/statsd"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"

	"github.com/falcosecurity/falcosidekick/types"
)

// NewGCPClient returns a new output.Client for accessing the GCP API.
func NewGCPClient(config *types.Configuration, stats *types.Statistics, promStats *types.PromStatistics, statsdClient, dogstatsdClient *statsd.Client) (*Client, error) {
	base64decodedCredentialsData, err := base64.StdEncoding.DecodeString(config.GCP.Credentials)
	if err != nil {
		log.Printf("[ERROR] : GCP - %v\n", "Error while base64-decoding GCP Credentials")
		return nil, errors.New("Error while base64-decoding GCP Credentials")
	}

	googleCredentialsData := string(base64decodedCredentialsData)
	var topicClient *pubsub.Topic
	var storageClient *storage.Client

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

	if config.GCP.Storage.Bucket != "" {
		credentials, err := google.CredentialsFromJSON(context.Background(), []byte(googleCredentialsData))
		if err != nil {
			log.Printf("[ERROR] : GCP Storage - %v\n", "Error while loading GCS Credentials")
			return nil, errors.New("Error while loading GCP Credentials")
		}
		storageClient, err = storage.NewClient(context.Background(), option.WithCredentials(credentials))
		if err != nil {
			log.Printf("[ERROR] : GCP Storage - %v\n", "Error while creating GCP Storage Client")
			return nil, errors.New("Error while creating GCP Storage Client")
		}
	}

	return &Client{
		OutputType:       "GCP",
		Config:           config,
		GCPTopicClient:   topicClient,
		GCSStorageClient: storageClient,
		Stats:            stats,
		PromStats:        promStats,
		StatsdClient:     statsdClient,
		DogstatsdClient:  dogstatsdClient,
	}, nil
}

// GCPPublishTopic sends a message to a GCP PubSub Topic
func (c *Client) GCPPublishTopic(falcopayload types.FalcoPayload) {
	c.Stats.GCPPubSub.Add(Total, 1)

	payload, _ := json.Marshal(falcopayload)
	message := &pubsub.Message{
		Data: payload,
	}

	result := c.GCPTopicClient.Publish(context.Background(), message)
	id, err := result.Get(context.Background())
	if err != nil {
		log.Printf("[ERROR] : GCPPubSub - %v - %v\n", "Error while publishing message", err.Error())
		c.Stats.GCPPubSub.Add(Error, 1)
		go c.CountMetric("outputs", 1, []string{"output:gcppubsub", "status:error"})
		c.PromStats.Outputs.With(map[string]string{"destination": "gcppubsub", "status": Error}).Inc()

		return
	}

	log.Printf("[INFO]  : GCPPubSub - Send to topic OK (%v)\n", id)
	c.Stats.GCPPubSub.Add(OK, 1)
	go c.CountMetric("outputs", 1, []string{"output:gcppubsub", "status:ok"})
	c.PromStats.Outputs.With(map[string]string{"destination": "gcppubsub", "status": OK}).Inc()
}

// UploadGCS upload payload to
func (c *Client) UploadGCS(falcopayload types.FalcoPayload) {
	c.Stats.GCPStorage.Add(Total, 1)

	payload, _ := json.Marshal(falcopayload)

	prefix := ""
	t := time.Now()
	if c.Config.GCP.Storage.Prefix != "" {
		prefix = c.Config.GCP.Storage.Prefix
	}

	key := fmt.Sprintf("%s/%s/%s.json", prefix, t.Format("2006-01-02"), t.Format(time.RFC3339Nano))
	fmt.Println(payload)
	_, err := c.GCSStorageClient.Bucket(c.Config.GCP.Storage.Bucket).Object(key).NewWriter(context.Background()).Write(payload)
	if err != nil {
		log.Printf("[ERROR] : GCPStorage - %v - %v\n", "Error while Uploading message", err.Error())
		c.Stats.GCPStorage.Add(Error, 1)
		go c.CountMetric("outputs", 1, []string{"output:gcpstorage", "status:error"})
		c.PromStats.Outputs.With(map[string]string{"destination": "gcpstorage", "status": Error}).Inc()
		return
	}

	log.Printf("[INFO]  : GCPStorage - Uploaded to bucket OK \n")
	c.Stats.GCPStorage.Add(OK, 1)
	go c.CountMetric("outputs", 1, []string{"output:gcpstorage", "status:ok"})
	c.PromStats.Outputs.With(map[string]string{"destination": "gcpstorage", "status": OK}).Inc()
}
