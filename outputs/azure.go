// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	azeventhubs "github.com/Azure/azure-sdk-for-go/sdk/messaging/azeventhubs"
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
