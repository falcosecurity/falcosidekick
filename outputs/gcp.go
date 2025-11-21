// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	gcpfunctions "cloud.google.com/go/functions/apiv1"
	"cloud.google.com/go/pubsub"
	"cloud.google.com/go/storage"
	"github.com/DataDog/datadog-go/statsd"
	"github.com/googleapis/gax-go/v2"
	"go.opentelemetry.io/otel/attribute"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
	gcpfunctionspb "google.golang.org/genproto/googleapis/cloud/functions/v1"

	"github.com/falcosecurity/falcosidekick/internal/pkg/utils"
	otlpmetrics "github.com/falcosecurity/falcosidekick/outputs/otlp_metrics"
	"github.com/falcosecurity/falcosidekick/types"
)

// NewGCPClient returns a new output.Client for accessing the GCP API.
func NewGCPClient(config *types.Configuration, stats *types.Statistics, promStats *types.PromStatistics,
	otlpMetrics *otlpmetrics.OTLPMetrics, statsdClient, dogstatsdClient *statsd.Client) (*Client, error) {
	base64decodedCredentialsData, err := base64.StdEncoding.DecodeString(config.GCP.Credentials)
	if err != nil {
		utils.Log(utils.ErrorLvl, "GCP", "Erroc.OutputTyper while base64-decoding GCP Credentials")
		return nil, errors.New("error while base64-decoding GCP Credentials")
	}

	googleCredentialsData := string(base64decodedCredentialsData)
	var topicClient *pubsub.Topic
	var storageClient *storage.Client
	var cloudFunctionsClient *gcpfunctions.CloudFunctionsClient
	var chronicleHTTPClient *http.Client
	var chronicleTokenSource oauth2.TokenSource

	if config.GCP.PubSub.ProjectID != "" && config.GCP.PubSub.Topic != "" {
		if googleCredentialsData != "" {
			credentials, err := google.CredentialsFromJSON(context.Background(), []byte(googleCredentialsData), pubsub.ScopePubSub)
			if err != nil {
				utils.Log(utils.ErrorLvl, "GCP PubSub", "Error while loading GCP Credentials")
				return nil, errors.New("error while loading GCP Credentials")
			}
			pubSubClient, err := pubsub.NewClient(context.Background(), config.GCP.PubSub.ProjectID, option.WithCredentials(credentials))
			if err != nil {
				utils.Log(utils.ErrorLvl, "GCP PubSub", "Error while creating GCP PubSub Client")
				return nil, errors.New("error while creating GCP PubSub Client")
			}
			topicClient = pubSubClient.Topic(config.GCP.PubSub.Topic)
		} else {
			pubSubClient, err := pubsub.NewClient(context.Background(), config.GCP.PubSub.ProjectID)
			if err != nil {
				utils.Log(utils.ErrorLvl, "GCP PubSub", "Error while creating GCP PubSub Client")
				return nil, errors.New("error while creating GCP PubSub Client")
			}
			topicClient = pubSubClient.Topic(config.GCP.PubSub.Topic)
		}
	}

	if config.GCP.Storage.Bucket != "" {
		credentials, err := google.CredentialsFromJSON(context.Background(), []byte(googleCredentialsData), storage.ScopeReadWrite)
		if err != nil {
			utils.Log(utils.ErrorLvl, "GCP PubSub", "Error while loading GCS Credentials")
			return nil, errors.New("error while loading GCP Credentials")
		}
		storageClient, err = storage.NewClient(context.Background(), option.WithCredentials(credentials))
		if err != nil {
			utils.Log(utils.ErrorLvl, "GCP PubSub", "Error while creating GCP Storage Client")
			return nil, errors.New("error while creating GCP Storage Client")
		}
	}

	if config.GCP.CloudFunctions.Name != "" {
		if googleCredentialsData != "" {
			credentials, err := google.CredentialsFromJSON(context.Background(), []byte(googleCredentialsData), gcpfunctions.DefaultAuthScopes()...)
			if err != nil {
				utils.Log(utils.ErrorLvl, "GCP CloudFunctions", "Error while loading GCS Credentials")
				return nil, errors.New("error while loading GCP Credentials")
			}
			cloudFunctionsClient, err = gcpfunctions.NewCloudFunctionsClient(context.Background(), option.WithCredentials(credentials))
			if err != nil {
				utils.Log(utils.ErrorLvl, "GCP CloudFunctions", "Error while creating GCP CloudFunctions Client")
				return nil, errors.New("error while creating GCP CloudFunctions Client")
			}
		} else {
			cloudFunctionsClient, err = gcpfunctions.NewCloudFunctionsClient(context.Background())
			if err != nil {
				utils.Log(utils.ErrorLvl, "GCP CloudFunctions", "Error while creating GCP CloudFunctions Client")
				return nil, errors.New("error while creating GCP CloudFunctions Client")
			}
		}
	}

	// Initialize Chronicle client and token source if all required fields are configured
	if config.GCP.Chronicle.MinimumPriority != "" &&
		config.GCP.Chronicle.Region != "" &&
		config.GCP.Chronicle.ProjectID != "" &&
		config.GCP.Chronicle.InstanceID != "" {
		ctx := context.Background()
		chronicleHTTPClient = &http.Client{
			Timeout: 30 * time.Second,
		}

		if googleCredentialsData != "" {
			credentials, err := google.CredentialsFromJSON(ctx, []byte(googleCredentialsData), "https://www.googleapis.com/auth/cloud-platform")
			if err != nil {
				utils.Log(utils.ErrorLvl, "GCP Chronicle", "Error while loading GCP Credentials")
				return nil, errors.New("error while loading GCP Credentials for Chronicle")
			}
			chronicleTokenSource = credentials.TokenSource
		} else {
			// Fallback to Default Token Source (ADC)
			ts, err := google.DefaultTokenSource(ctx, "https://www.googleapis.com/auth/cloud-platform")
			if err != nil {
				utils.Log(utils.ErrorLvl, "GCP Chronicle", "Error while getting Default Token Source")
				return nil, errors.New("error while getting Default Token Source for Chronicle")
			}
			chronicleTokenSource = ts
		}
	}

	return &Client{
		OutputType:              "GCP",
		Config:                  config,
		GCPTopicClient:          topicClient,
		GCSStorageClient:        storageClient,
		GCPCloudFunctionsClient: cloudFunctionsClient,
		GCPChronicleClient:      chronicleHTTPClient,
		GCPTokenSource:          chronicleTokenSource,
		Stats:                   stats,
		PromStats:               promStats,
		OTLPMetrics:             otlpMetrics,
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
		utils.Log(utils.ErrorLvl, c.OutputType+" CloudFunctions", fmt.Sprintf("Error while calling CloudFunction: %v", err))
		c.Stats.GCPPubSub.Add(Error, 1)
		go c.CountMetric("outputs", 1, []string{"output:gcpcloudfunctions", "status:error"})
		c.PromStats.Outputs.With(map[string]string{"destination": "gcpcloudfunctions", "status": Error}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "gcpcloudfunctions"),
			attribute.String("status", Error)).Inc()
		return
	}

	utils.Log(utils.ErrorLvl, c.OutputType+" CloudFunctions", fmt.Sprintf("Call CloudFunction OK (%v)", result.ExecutionId))
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
		utils.Log(utils.ErrorLvl, c.OutputType+" PubSub", fmt.Sprintf("Error while publishing message: %v", err))
		c.Stats.GCPPubSub.Add(Error, 1)
		go c.CountMetric("outputs", 1, []string{"output:gcppubsub", "status:error"})
		c.PromStats.Outputs.With(map[string]string{"destination": "gcppubsub", "status": Error}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "gcppubsub"),
			attribute.String("status", Error)).Inc()
		return
	}

	utils.Log(utils.InfoLvl, c.OutputType+" PubSub", fmt.Sprintf("Send to topic OK (%v)", id))
	c.Stats.GCPPubSub.Add(OK, 1)
	go c.CountMetric("outputs", 1, []string{"output:gcppubsub", "status:ok"})
	c.PromStats.Outputs.With(map[string]string{"destination": "gcppubsub", "status": OK}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "gcppubsub"),
		attribute.String("status", OK)).Inc()
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
		utils.Log(utils.ErrorLvl, c.OutputType+"Storage", fmt.Sprintf("Error while Uploading message: %v", err))
		c.Stats.GCPStorage.Add(Error, 1)
		go c.CountMetric("outputs", 1, []string{"output:gcpstorage", "status:error"})
		c.PromStats.Outputs.With(map[string]string{"destination": "gcpstorage", "status": Error}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "gcpstorage"),
			attribute.String("status", Error)).Inc()
		return
	}
	if n == 0 {
		utils.Log(utils.ErrorLvl, c.OutputType+"Storage", "Empty payload uploaded")
		c.Stats.GCPStorage.Add(Error, 1)
		go c.CountMetric("outputs", 1, []string{"output:gcpstorage", "status:error"})
		c.PromStats.Outputs.With(map[string]string{"destination": "gcpstorage", "status": Error}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "gcpstorage"),
			attribute.String("status", Error)).Inc()
		return
	}
	if err := bucketWriter.Close(); err != nil {
		utils.Log(utils.ErrorLvl, c.OutputType+"Storage", fmt.Sprintf("Error while closing the writer: %v", err))
		c.Stats.GCPStorage.Add(Error, 1)
		go c.CountMetric("outputs", 1, []string{"output:gcpstorage", "status:error"})
		c.PromStats.Outputs.With(map[string]string{"destination": "gcpstorage", "status": Error}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "gcpstorage"),
			attribute.String("status", Error)).Inc()
		return
	}

	utils.Log(utils.InfoLvl, c.OutputType+"Storage", "Upload to bucket OK")
	c.Stats.GCPStorage.Add(OK, 1)
	go c.CountMetric("outputs", 1, []string{"output:gcpstorage", "status:ok"})
	c.PromStats.Outputs.With(map[string]string{"destination": "gcpstorage", "status": OK}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "gcpstorage"),
		attribute.String("status", OK)).Inc()
}

// GCPChronicleIngest sends a Falco event to Google Chronicle as unstructured log
func (c *Client) GCPChronicleIngest(falcopayload types.FalcoPayload) {
	// ensure client and token source are initialized
	if c.GCPChronicleClient == nil || c.GCPTokenSource == nil {
		utils.Log(utils.ErrorLvl, c.OutputType+" Chronicle", "Chronicle client or token source not initialized")
		c.Stats.GCPChronicle.Add(Error, 1)
		go c.CountMetric(Outputs, 1, []string{"output:gcpchronicle", "status:error"})
		c.PromStats.Outputs.With(map[string]string{"destination": "gcpchronicle", "status": Error}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "gcpchronicle"),
			attribute.String("status", Error)).Inc()
		return
	}

	c.Stats.GCPChronicle.Add(Total, 1)

	// Marshal FalcoPayload to JSON
	payloadBytes, err := json.Marshal(falcopayload)
	if err != nil {
		utils.Log(utils.ErrorLvl, c.OutputType+" Chronicle", fmt.Sprintf("Error marshaling payload: %v", err))
		c.Stats.GCPChronicle.Add(Error, 1)
		go c.CountMetric(Outputs, 1, []string{"output:gcpchronicle", "status:error"})
		c.PromStats.Outputs.With(map[string]string{"destination": "gcpchronicle", "status": Error}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "gcpchronicle"),
			attribute.String("status", Error)).Inc()
		return
	}

	// Format: projects/{project}/locations/{location}/instances/{instance}
	parent := fmt.Sprintf("projects/%s/locations/%s/instances/%s",
		c.Config.GCP.Chronicle.ProjectID,
		c.Config.GCP.Chronicle.Region,
		c.Config.GCP.Chronicle.InstanceID)

	// The v1beta API requires the 'data' field to be a base64-encoded string.
	encodedData := base64.StdEncoding.EncodeToString(payloadBytes)

	logEntryTime := falcopayload.Time
	collectionTime := time.Now()
	// collectionTime must be after logEntryTime
	if !collectionTime.After(logEntryTime) {
		collectionTime = logEntryTime.Add(time.Second)
	}

	// Construct the Log object
	logEntry := map[string]interface{}{
		"data":           encodedData,
		"logEntryTime":   logEntryTime.Format(time.RFC3339),
		"collectionTime": collectionTime.Format(time.RFC3339),
	}

	batchRequest := map[string]interface{}{
		"inlineSource": map[string]interface{}{
			"logs": []interface{}{logEntry},
		},
	}

	requestBody, err := json.Marshal(batchRequest)
	if err != nil {
		utils.Log(utils.ErrorLvl, c.OutputType+" Chronicle", fmt.Sprintf("Error marshaling request: %v", err))
		c.Stats.GCPChronicle.Add(Error, 1)
		go c.CountMetric(Outputs, 1, []string{"output:gcpchronicle", "status:error"})
		c.PromStats.Outputs.With(map[string]string{"destination": "gcpchronicle", "status": Error}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "gcpchronicle"),
			attribute.String("status", Error)).Inc()
		return
	}

	// This handles refresh automatically
	token, err := c.GCPTokenSource.Token()
	if err != nil {
		utils.Log(utils.ErrorLvl, c.OutputType+" Chronicle", fmt.Sprintf("Error getting OAuth2 token: %v", err))
		c.Stats.GCPChronicle.Add(Error, 1)
		go c.CountMetric(Outputs, 1, []string{"output:gcpchronicle", "status:error"})
		c.PromStats.Outputs.With(map[string]string{"destination": "gcpchronicle", "status": Error}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "gcpchronicle"),
			attribute.String("status", Error)).Inc()
		return
	}

	// Format: https://chronicle.{region}.rep.googleapis.com/v1beta/{parent}/logTypes/{logType}/logs:import
	endpoint := fmt.Sprintf("https://chronicle.%s.rep.googleapis.com/v1beta/%s/logTypes/%s/logs:import",
		c.Config.GCP.Chronicle.Region,
		parent,
		c.Config.GCP.Chronicle.LogType)

	req, err := http.NewRequestWithContext(context.Background(), "POST", endpoint, bytes.NewBuffer(requestBody))
	if err != nil {
		utils.Log(utils.ErrorLvl, c.OutputType+" Chronicle", fmt.Sprintf("Error creating HTTP request: %v", err))
		c.Stats.GCPChronicle.Add(Error, 1)
		go c.CountMetric(Outputs, 1, []string{"output:gcpchronicle", "status:error"})
		c.PromStats.Outputs.With(map[string]string{"destination": "gcpchronicle", "status": Error}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "gcpchronicle"),
			attribute.String("status", Error)).Inc()
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token.AccessToken))

	resp, err := c.GCPChronicleClient.Do(req)
	if err != nil {
		utils.Log(utils.ErrorLvl, c.OutputType+" Chronicle", fmt.Sprintf("Error sending request: %v", err))
		c.Stats.GCPChronicle.Add(Error, 1)
		go c.CountMetric(Outputs, 1, []string{"output:gcpchronicle", "status:error"})
		c.PromStats.Outputs.With(map[string]string{"destination": "gcpchronicle", "status": Error}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "gcpchronicle"),
			attribute.String("status", Error)).Inc()
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		utils.Log(utils.ErrorLvl, c.OutputType+" Chronicle", fmt.Sprintf("Error response from Chronicle API: %d", resp.StatusCode))
		c.Stats.GCPChronicle.Add(Error, 1)
		go c.CountMetric(Outputs, 1, []string{"output:gcpchronicle", "status:error"})
		c.PromStats.Outputs.With(map[string]string{"destination": "gcpchronicle", "status": Error}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "gcpchronicle"),
			attribute.String("status", Error)).Inc()
		return
	}

	utils.Log(utils.InfoLvl, c.OutputType+" Chronicle", "Import log OK")
	c.Stats.GCPChronicle.Add(OK, 1)
	go c.CountMetric(Outputs, 1, []string{"output:gcpchronicle", "status:ok"})
	c.PromStats.Outputs.With(map[string]string{"destination": "gcpchronicle", "status": OK}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "gcpchronicle"),
		attribute.String("status", OK)).Inc()
}
