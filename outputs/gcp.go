// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	gcpfunctions "cloud.google.com/go/functions/apiv1"
	"cloud.google.com/go/storage"
	gcpfunctionspb "google.golang.org/genproto/googleapis/cloud/functions/v1"

	"cloud.google.com/go/pubsub"
	"github.com/DataDog/datadog-go/statsd"
	"github.com/googleapis/gax-go/v2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"

	"github.com/falcosecurity/falcosidekick/types"
)

// NewGCPClient returns a new output.Client for accessing the GCP API.
func NewGCPClient(config *types.Configuration, stats *types.Statistics, promStats *types.PromStatistics, statsdClient, dogstatsdClient *statsd.Client) (*Client, error) {
	base64decodedCredentialsData, err := base64.StdEncoding.DecodeString(config.GCP.Credentials)
	if err != nil {
		log.Printf("[ERROR] : GCP - %v\n", "Error while base64-decoding GCP Credentials")
		return nil, errors.New("error while base64-decoding GCP Credentials")
	}

	googleCredentialsData := string(base64decodedCredentialsData)
	var topicClient *pubsub.Topic
	var storageClient *storage.Client
	var cloudFunctionsClient *gcpfunctions.CloudFunctionsClient

	if config.GCP.PubSub.ProjectID != "" && config.GCP.PubSub.Topic != "" {
		if googleCredentialsData != "" {
			credentials, err := google.CredentialsFromJSON(context.Background(), []byte(googleCredentialsData), pubsub.ScopePubSub)
			if err != nil {
				log.Printf("[ERROR] : GCP PubSub - %v\n", "Error while loading GCP Credentials")
				return nil, errors.New("error while loading GCP Credentials")
			}
			pubSubClient, err := pubsub.NewClient(context.Background(), config.GCP.PubSub.ProjectID, option.WithCredentials(credentials))
			if err != nil {
				log.Printf("[ERROR] : GCP PubSub - %v\n", "Error while creating GCP PubSub Client")
				return nil, errors.New("error while creating GCP PubSub Client")
			}
			topicClient = pubSubClient.Topic(config.GCP.PubSub.Topic)
		} else {
			pubSubClient, err := pubsub.NewClient(context.Background(), config.GCP.PubSub.ProjectID)
			if err != nil {
				log.Printf("[ERROR] : GCP PubSub - %v\n", "Error while creating GCP PubSub Client")
				return nil, errors.New("error while creating GCP PubSub Client")
			}
			topicClient = pubSubClient.Topic(config.GCP.PubSub.Topic)
		}
	}

	if config.GCP.Storage.Bucket != "" {
		credentials, err := google.CredentialsFromJSON(context.Background(), []byte(googleCredentialsData))
		if err != nil {
			log.Printf("[ERROR] : GCP Storage - %v\n", "Error while loading GCS Credentials")
			return nil, errors.New("error while loading GCP Credentials")
		}
		storageClient, err = storage.NewClient(context.Background(), option.WithCredentials(credentials))
		if err != nil {
			log.Printf("[ERROR] : GCP Storage - %v\n", "Error while creating GCP Storage Client")
			return nil, errors.New("error while creating GCP Storage Client")
		}
	}

	if config.GCP.CloudFunctions.Name != "" {
		if googleCredentialsData != "" {
			credentials, err := google.CredentialsFromJSON(context.Background(), []byte(googleCredentialsData), gcpfunctions.DefaultAuthScopes()...)
			if err != nil {
				log.Printf("[ERROR] : GCP CloudFunctions - %v\n", "Error while loading GCS Credentials")
				return nil, errors.New("error while loading GCP Credentials")
			}
			cloudFunctionsClient, err = gcpfunctions.NewCloudFunctionsClient(context.Background(), option.WithCredentials(credentials))
			if err != nil {
				log.Printf("[ERROR]: GCP CloudFunctions - %v\n", "Error while creating GCP CloudFunctions Client")
				return nil, errors.New("error while creating GCP CloudFunctions Client")
			}
		} else {
			cloudFunctionsClient, err = gcpfunctions.NewCloudFunctionsClient(context.Background())
			if err != nil {
				log.Printf("[ERROR]: GCP CloudFunctions - %v\n", "Error while creating GCP CloudFunctions Client")
				return nil, errors.New("error while creating GCP CloudFunctions Client")
			}
		}
	}

	return &Client{
		OutputType:              "GCP",
		Config:                  config,
		GCPTopicClient:          topicClient,
		GCSStorageClient:        storageClient,
		GCPCloudFunctionsClient: cloudFunctionsClient,
		Stats:                   stats,
		PromStats:               promStats,
		StatsdClient:            statsdClient,
		DogstatsdClient:         dogstatsdClient,
	}, nil
}

// GCPCallCloudFunction calls the given Cloud Function
func (c *Client) GCPCallCloudFunction(falcopayload types.FalcoPayload) {
	c.Stats.GCPCloudFunctions.Add(Total, 1)

	payload, _ := json.Marshal(falcopayload)
	data := string(payload)

	result, err := c.GCPCloudFunctionsClient.CallFunction(context.Background(), &gcpfunctionspb.CallFunctionRequest{
		Name: c.Config.GCP.CloudFunctions.Name,
		Data: data,
	}, gax.WithGRPCOptions())

	if err != nil {
		log.Printf("[ERROR] : GCPCloudFunctions - %v - %v\n", "Error while calling CloudFunction", err.Error())
		c.Stats.GCPPubSub.Add(Error, 1)
		go c.CountMetric("outputs", 1, []string{"output:gcpcloudfunctions", "status:error"})
		c.PromStats.Outputs.With(map[string]string{"destination": "gcpcloudfunctions", "status": Error}).Inc()

		return
	}

	log.Printf("[INFO]  : GCPCloudFunctions - Call CloudFunction OK (%v)\n", result.ExecutionId)
	c.Stats.GCPCloudFunctions.Add(OK, 1)
	go c.CountMetric("outputs", 1, []string{"output:gcpcloudfunctions", "status:ok"})

}

// GCPPublishTopic sends a message to a GCP PubSub Topic
func (c *Client) GCPPublishTopic(falcopayload types.FalcoPayload) {
	c.Stats.GCPPubSub.Add(Total, 1)

	payload, _ := json.Marshal(falcopayload)
	message := &pubsub.Message{
		Data:       payload,
		Attributes: c.Config.GCP.PubSub.CustomAttributes,
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
	bucketWriter := c.GCSStorageClient.Bucket(c.Config.GCP.Storage.Bucket).Object(key).NewWriter(context.Background())
	n, err := bucketWriter.Write(payload)
	if err != nil {
		log.Printf("[ERROR] : GCPStorage - %v - %v\n", "Error while Uploading message", err.Error())
		c.Stats.GCPStorage.Add(Error, 1)
		go c.CountMetric("outputs", 1, []string{"output:gcpstorage", "status:error"})
		c.PromStats.Outputs.With(map[string]string{"destination": "gcpstorage", "status": Error}).Inc()
		return
	}
	if n == 0 {
		log.Printf("[ERROR] : GCPStorage - %v\n", "Empty payload uploaded")
		c.Stats.GCPStorage.Add(Error, 1)
		go c.CountMetric("outputs", 1, []string{"output:gcpstorage", "status:error"})
		c.PromStats.Outputs.With(map[string]string{"destination": "gcpstorage", "status": Error}).Inc()
		return
	}
	if err := bucketWriter.Close(); err != nil {
		log.Printf("[ERROR] : GCPStorage - %v - %v\n", "Error while closing the writer", err.Error())
		c.Stats.GCPStorage.Add(Error, 1)
		go c.CountMetric("outputs", 1, []string{"output:gcpstorage", "status:error"})
		c.PromStats.Outputs.With(map[string]string{"destination": "gcpstorage", "status": Error}).Inc()
		return
	}

	log.Printf("[INFO]  : GCPStorage - Upload to bucket OK \n")
	c.Stats.GCPStorage.Add(OK, 1)
	go c.CountMetric("outputs", 1, []string{"output:gcpstorage", "status:ok"})
	c.PromStats.Outputs.With(map[string]string{"destination": "gcpstorage", "status": OK}).Inc()
}
