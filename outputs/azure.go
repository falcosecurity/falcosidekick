package outputs

import (
	"context"
	"encoding/json"
	"log"
	"time"

	eventhub "github.com/Azure/azure-event-hubs-go/v3"
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
	log.Printf("[INFO]  : Try sending event")
	hub, err := eventhub.NewHubWithNamespaceNameAndEnvironment(c.Config.Azure.EventHub.Namespace, c.Config.Azure.EventHub.Name)
	if err != nil {
		c.Stats.AzureEventHub.Add("error", 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "azureeventhub", "status": "error"}).Inc()
		log.Printf("[ERROR] : %v EventHub - %v\n", c.OutputType, err.Error())
		return
	}
	log.Printf("[INFO]  : %v EventHub - Hub client created\n", c.OutputType)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)

	defer cancel()
	data, err := json.Marshal(falcopayload)
	if err != nil {
		c.Stats.AzureEventHub.Add("error", 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "azureeventhub", "status": "error"}).Inc()
		log.Printf("[ERROR] : Cannot marshal payload: %v", err.Error())
		return
	}
	err = hub.Send(ctx, eventhub.NewEvent(data))
	if err != nil {
		c.Stats.AzureEventHub.Add("error", 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "azureeventhub", "status": "error"}).Inc()
		log.Printf("[ERROR] : %v EventHub - %v\n", c.OutputType, err.Error())
		return
	}
	c.Stats.AzureEventHub.Add("ok", 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "azureeventhub", "status": "ok"}).Inc()
	log.Printf("[INFO]  : Succesfully sent event")

	c.Stats.AzureEventHub.Add("total", 1)
}
