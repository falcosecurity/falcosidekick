// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	azeventhubs "github.com/Azure/azure-sdk-for-go/sdk/messaging/azeventhubs"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azdatalake/file"
	"github.com/DataDog/datadog-go/statsd"
	"go.opentelemetry.io/otel/attribute"

	"github.com/falcosecurity/falcosidekick/internal/pkg/utils"
	otlpmetrics "github.com/falcosecurity/falcosidekick/outputs/otlp_metrics"
	"github.com/falcosecurity/falcosidekick/types"
)

// NewEventHubClient returns a new output.Client for accessing the Azure Event Hub.
func NewEventHubClient(config *types.Configuration, stats *types.Statistics, promStats *types.PromStatistics,
	otlpMetrics *otlpmetrics.OTLPMetrics, statsdClient, dogstatsdClient *statsd.Client) (*Client, error) {
	return &Client{
		OutputType:      "AzureEventHub",
		Config:          config,
		Stats:           stats,
		PromStats:       promStats,
		OTLPMetrics:     otlpMetrics,
		StatsdClient:    statsdClient,
		DogstatsdClient: dogstatsdClient,
	}, nil
}

// EventHubPost posts event to Azure Event Hub
func (c *Client) EventHubPost(falcopayload types.FalcoPayload) {
	c.Stats.AzureEventHub.Add(Total, 1)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	utils.Log(utils.InfoLvl, c.OutputType+" EventHub", "Try sending event")
	defaultAzureCred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		c.setEventHubErrorMetrics()
		utils.Log(utils.ErrorLvl, c.OutputType+" EventHub", err.Error())
		return
	}

	producerClient, err := azeventhubs.NewProducerClient(c.Config.Azure.EventHub.Namespace, c.Config.Azure.EventHub.Name, defaultAzureCred, nil)
	if err != nil {
		c.setEventHubErrorMetrics()
		utils.Log(utils.ErrorLvl, c.OutputType+" EventHub", err.Error())
		return
	}
	defer producerClient.Close(ctx)

	utils.Log(utils.InfoLvl, c.OutputType+" EventHub", "Hub client created")

	data, err := json.Marshal(falcopayload)
	if err != nil {
		c.setEventHubErrorMetrics()
		utils.Log(utils.ErrorLvl, c.OutputType+" EventHub", fmt.Sprintf("Cannot marshal payload: %v", err))
		return
	}

	batch, err := producerClient.NewEventDataBatch(ctx, nil)
	if err != nil {
		c.setEventHubErrorMetrics()
		utils.Log(utils.ErrorLvl, c.OutputType+" EventHub", fmt.Sprintf("Cannot marshal payload: %v", err))
		return
	}

	if err := batch.AddEventData(&azeventhubs.EventData{Body: data}, nil); err != nil {
		c.setEventHubErrorMetrics()
		utils.Log(utils.ErrorLvl, c.OutputType+" EventHub", fmt.Sprintf("Cannot marshal payload: %v", err))
		return
	}

	producerClient.SendEventDataBatch(ctx, batch, nil)
	if err := producerClient.SendEventDataBatch(ctx, batch, nil); err != nil {
		c.setEventHubErrorMetrics()
		utils.Log(utils.ErrorLvl, c.OutputType+" EventHub", err.Error())
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:azureeventhub", "status:ok"})
	c.Stats.AzureEventHub.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "azureeventhub", "status": OK}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "azureeventhub"),
		attribute.String("status", OK)).Inc()
	utils.Log(utils.InfoLvl, c.OutputType+" EventHub", "Publish OK")
}

// setEventHubErrorMetrics set the error stats
func (c *Client) setEventHubErrorMetrics() {
	go c.CountMetric(Outputs, 1, []string{"output:azureeventhub", "status:error"})
	c.Stats.AzureEventHub.Add(Error, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "azureeventhub", "status": Error}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "azureeventhub"),
		attribute.String("status", Error)).Inc()
}

func (c *Client) UploadBlob(falcopayload types.FalcoPayload) {
	f, _ := json.Marshal(falcopayload)

	prefix := ""
	t := time.Now()
	if c.Config.Azure.Blob.Prefix != "" {
		prefix = c.Config.Azure.Blob.Prefix
	}

	serviceURL := fmt.Sprintf("https://%s.dfs.core.windows.net/", c.Config.Azure.Blob.Account)
	key := fmt.Sprintf("%s/%s/%s.json", prefix, t.Format("2006-01-02"), t.Format(time.RFC3339Nano))

	utils.Log(utils.InfoLvl, c.OutputType+" Blob", "Try writing blob")
	defaultAzureCred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		c.setBlobErrorMetrics()
		utils.Log(utils.ErrorLvl, c.OutputType+" Blob", err.Error())
		return
	}

	// create a client for the specified storage account
	client, err := azblob.NewClient(serviceURL, defaultAzureCred, nil)
	if err != nil {
		c.setBlobErrorMetrics()
		utils.Log(utils.ErrorLvl, c.OutputType+" Blob",
			fmt.Sprintf("Error with acccount %s: %v", serviceURL, err))
		return
	}

	// upload the file to the specified container with the specified blob name
	// TODO: should any part of the response be validated here? aws s3 client performs a few checks
	_, err = client.UploadStream(context.TODO(), c.Config.Azure.Blob.Container, key, bytes.NewReader(f), nil)
	if err != nil {
		c.setBlobErrorMetrics()
		utils.Log(utils.ErrorLvl, c.OutputType+" Blob",
			fmt.Sprintf("Cannot upload file %s to %s: %v", key, serviceURL, err))

		go c.CountMetric("outputs", 1, []string{"output:azblob", "status:error"})
		c.PromStats.Outputs.With(map[string]string{"destination": "azblob", "status": Error}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "azblob"),
			attribute.String("status", Error)).Inc()
		utils.Log(utils.ErrorLvl, c.OutputType+" S3", err.Error())

		return
	}

	go c.CountMetric("outputs", 1, []string{"output:azblob", "status:ok"})
	c.PromStats.Outputs.With(map[string]string{"destination": "azblob", "status": "ok"}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "azblob"),
		attribute.String("status", OK)).Inc()
}

// setBlobErrorMetrics set the error stats
func (c *Client) setBlobErrorMetrics() {
	go c.CountMetric(Outputs, 1, []string{"output:azblob", "status:error"})
	c.Stats.AzureBlob.Add(Error, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "azblob", "status": Error}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "azblob"),
		attribute.String("status", Error)).Inc()
}

func (c *Client) UploadADLS(falcopayload types.FalcoPayload) {
	f, _ := json.Marshal(falcopayload)

	prefix := ""
	t := time.Now()
	if c.Config.Azure.ADLS.Prefix != "" {
		prefix = c.Config.Azure.ADLS.Prefix
	}

	serviceURL := fmt.Sprintf("https://%s.dfs.core.windows.net/", c.Config.Azure.ADLS.Account)
	key := fmt.Sprintf("%s/%s/%s.json", prefix, t.Format("2006-01-02"), t.Format(time.RFC3339Nano))

	utils.Log(utils.InfoLvl, c.OutputType+" ADLS Gen2 Blob", "Try writing ADLS blob")
	defaultAzureCred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		c.setADLSErrorMetrics()
		utils.Log(utils.ErrorLvl, c.OutputType+" ADLS Gen2 Blob", err.Error())
		return
	}

	// create a client for the specified storage account
	path, err := url.JoinPath(serviceURL, c.Config.Azure.ADLS.Container, key)
	if err != nil {
		c.setADLSErrorMetrics()
		utils.Log(utils.ErrorLvl, c.OutputType+" ADLS Gen2 Blob", err.Error())
		return
	}

	client, err := file.NewClient(path, defaultAzureCred, nil)
	if err != nil {
		c.setADLSErrorMetrics()
		utils.Log(utils.ErrorLvl, c.OutputType+" ADLS Gen2 Blob",
			fmt.Sprintf("Error with acccount %s: %v", serviceURL, err))
		return
	}

	// upload the file to the specified container with the specified blob name
	err = client.UploadStream(context.TODO(), bytes.NewReader(f), nil)
	if err != nil {
		c.setADLSErrorMetrics()
		utils.Log(utils.ErrorLvl, c.OutputType+" ADLS Gen2 Blob",
			fmt.Sprintf("Cannot upload file %s to %s: %v", key, serviceURL, err))

		go c.CountMetric("outputs", 1, []string{"output:azdatalake", "status:error"})
		c.PromStats.Outputs.With(map[string]string{"destination": "azdatalake", "status": Error}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "azdatalake"),
			attribute.String("status", Error)).Inc()
		utils.Log(utils.ErrorLvl, c.OutputType+" S3", err.Error())

		return
	}

	go c.CountMetric("outputs", 1, []string{"output:azdatalake", "status:ok"})
	c.PromStats.Outputs.With(map[string]string{"destination": "azdatalake", "status": "ok"}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "azdatalake"),
		attribute.String("status", OK)).Inc()
}

// setADLSErrorMetrics set the error stats
func (c *Client) setADLSErrorMetrics() {
	go c.CountMetric(Outputs, 1, []string{"output:azdatalake", "status:error"})
	c.Stats.AzureADLS.Add(Error, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "azdatalake", "status": Error}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "azdatalake"),
		attribute.String("status", Error)).Inc()
}
