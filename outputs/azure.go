// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	azeventhubs "github.com/Azure/azure-sdk-for-go/sdk/messaging/azeventhubs"
	"github.com/DataDog/datadog-go/statsd"

	"github.com/falcosecurity/falcosidekick/types"
)

// NewEventHubClient returns a new output.Client for accessing the Azure Event Hub.
func NewEventHubClient(config *types.Configuration, stats *types.Statistics, promStats *types.PromStatistics, statsdClient, dogstatsdClient *statsd.Client) (*Client, error) {
	return &Client{
		OutputType:      "AzureEventHub",
		Config:          config,
		Stats:           stats,
		PromStats:       promStats,
		StatsdClient:    statsdClient,
		DogstatsdClient: dogstatsdClient,
	}, nil
}

// EventHubPost posts event to Azure Event Hub
func (c *Client) EventHubPost(falcopayload types.FalcoPayload) {
	c.Stats.AzureEventHub.Add(Total, 1)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	log.Printf("[INFO] : %v EventHub - Try sending event", c.OutputType)
	defaultAzureCred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		c.setEventHubErrorMetrics()
		log.Printf("[ERROR] : %v EventHub - %v\n", c.OutputType, err.Error())
		return
	}

	producerClient, err := azeventhubs.NewProducerClient(c.Config.Azure.EventHub.Namespace, c.Config.Azure.EventHub.Name, defaultAzureCred, nil)
	if err != nil {
		c.setEventHubErrorMetrics()
		log.Printf("[ERROR] : %v EventHub - %v\n", c.OutputType, err.Error())
		return
	}
	defer producerClient.Close(ctx)

	log.Printf("[INFO]  : %v EventHub - Hub client created\n", c.OutputType)

	data, err := json.Marshal(falcopayload)
	if err != nil {
		c.setEventHubErrorMetrics()
		log.Printf("[ERROR] : Cannot marshal payload: %v", err.Error())
		return
	}

	batch, err := producerClient.NewEventDataBatch(ctx, nil)
	if err != nil {
		c.setEventHubErrorMetrics()
		log.Printf("[ERROR] : Cannot marshal payload: %v", err.Error())
		return
	}

	if err := batch.AddEventData(&azeventhubs.EventData{Body: data}, nil); err != nil {
		c.setEventHubErrorMetrics()
		log.Printf("[ERROR] : Cannot marshal payload: %v", err.Error())
		return
	}

	producerClient.SendEventDataBatch(ctx, batch, nil)
	if err := producerClient.SendEventDataBatch(ctx, batch, nil); err != nil {
		c.setEventHubErrorMetrics()
		log.Printf("[ERROR] : %v EventHub - %v\n", c.OutputType, err.Error())
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:azureeventhub", "status:ok"})
	c.Stats.AzureEventHub.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "azureeventhub", "status": OK}).Inc()
	log.Printf("[INFO]  : %v EventHub - Publish OK", c.OutputType)
}

// setEventHubErrorMetrics set the error stats
func (c *Client) setEventHubErrorMetrics() {
	go c.CountMetric(Outputs, 1, []string{"output:azureeventhub", "status:error"})
	c.Stats.AzureEventHub.Add(Error, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "azureeventhub", "status": Error}).Inc()
}
