// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"fmt"
	"log"

	"github.com/falcosecurity/falcosidekick/types"
)

type QuickwitDynamicMapping struct {
	Description string `json:"description"`
	Fast        bool   `json:"fast"`
	ExpendDots  bool   `json:"expand_dots"`
	Indexed     bool   `json:"indexed"`
	Record      string `json:"record"`
	Stored      bool   `json:"stored"`
	Tokenizer   string `json:"tokenizer"`
}

type QuickwitFieldMapping struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Fast bool   `json:"fast"`
}

type QuickwitSearchSettings struct {
	DefaultSearchFields []string `json:"default_search_fields"`
}

type QuickwitDocMapping struct {
	DynamicMapping QuickwitDynamicMapping `json:"dynamic_mapping"`
	FieldMappings  []QuickwitFieldMapping `json:"field_mappings"`
	Mode           string                 `json:"mode"`
	StoreSource    bool                   `json:"store_source"`
	TimestampField string                 `json:"timestamp_field"`
}

type QuickwitMappingPayload struct {
	Id             string                 `json:"index_id"`
	Version        string                 `json:"version"`
	SearchSettings QuickwitSearchSettings `json:"search_settings"`
	DocMapping     QuickwitDocMapping     `json:"doc_mapping"`
}

func (c *Client) checkQuickwitIndexAlreadyExists(args types.InitClientArgs) bool {
	config := args.Config.Quickwit

	endpointUrl := fmt.Sprintf("%s/%s/indexes/%s/describe", config.HostPort, config.ApiEndpoint, config.Index)
	quickwitCheckClient, err := NewClient("QuickwitCheckAlreadyExists", endpointUrl, config.MutualTLS, config.CheckCert, args)
	if err != nil {
		return false
	}

	if nil != quickwitCheckClient.sendRequest("GET", "") {
		return false
	}

	return true
}

func (c *Client) AutoCreateQuickwitIndex(args types.InitClientArgs) error {
	config := args.Config.Quickwit

	if c.checkQuickwitIndexAlreadyExists(args) {
		return nil
	}

	endpointUrl := fmt.Sprintf("%s/%s/indexes", config.HostPort, config.ApiEndpoint)
	quickwitInitClient, err := NewClient("QuickwitInit", endpointUrl, config.MutualTLS, config.CheckCert, args)
	if err != nil {
		return err
	}

	mapping := &QuickwitMappingPayload{
		Id:      config.Index,
		Version: config.Version,
		DocMapping: QuickwitDocMapping{
			Mode:           "dynamic",
			StoreSource:    true,
			TimestampField: "time",
			DynamicMapping: QuickwitDynamicMapping{
				Description: "Falco",
				Fast:        true,
				ExpendDots:  true,
				Indexed:     true,
				Stored:      true,
				Record:      "basic",
				Tokenizer:   "raw",
			},
			FieldMappings: []QuickwitFieldMapping{
				{
					Name: "time",
					Type: "datetime",
					Fast: true,
				},
				{
					Name: "uuid",
					Type: "text",
					Fast: true,
				},
				{
					Name: "hostname",
					Type: "text",
					Fast: true,
				},
				{
					Name: "priority",
					Type: "text",
					Fast: true,
				},
				{
					Name: "source",
					Type: "text",
					Fast: true,
				},
				{
					Name: "output",
					Type: "text",
				},
				{
					Name: "rule",
					Type: "text",
					Fast: true,
				},
				{
					Name: "tags",
					Type: "array<text>",
					Fast: true,
				},
				{
					Name: "output_fields",
					Type: "json",
					Fast: true,
				},
			},
		},
		SearchSettings: QuickwitSearchSettings{
			DefaultSearchFields: []string{"rule", "source", "output", "priority", "hostname", "tags"},
		},
	}

	if args.Config.Debug {
		log.Printf("[DEBUG] : Quickwit - mapping: %#v\n", mapping)
	}

	err = quickwitInitClient.Post(mapping)

	// This error means it's an http 400 (meaning the index already exists, so no need to throw an error)
	if err != nil && err.Error() == "header missing" {
		return nil
	}

	return err
}

func (c *Client) QuickwitPost(falcopayload types.FalcoPayload) {
	c.Stats.Quickwit.Add(Total, 1)

	if len(c.Config.Quickwit.CustomHeaders) != 0 {
		c.httpClientLock.Lock()
		defer c.httpClientLock.Unlock()
		for i, j := range c.Config.Quickwit.CustomHeaders {
			c.AddHeader(i, j)
		}
	}

	if c.Config.Debug {
		log.Printf("[DEBUG] : Quickwit - ingesting payload: %v\n", falcopayload)
	}

	err := c.Post(falcopayload)

	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:quickwit", "status:error"})
		c.Stats.Quickwit.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "quickwit", "status": Error}).Inc()
		log.Printf("[ERROR] : Quickwit - %v\n", err.Error())
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:quickwit", "status:ok"})
	c.Stats.Quickwit.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "quickwit", "status": OK}).Inc()
}
