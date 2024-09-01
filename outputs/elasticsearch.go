// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/falcosecurity/falcosidekick/internal/pkg/batcher"
	"github.com/falcosecurity/falcosidekick/types"
)

type eSPayload struct {
	types.FalcoPayload
	Timestamp time.Time `json:"@timestamp"`
}

type esResponse struct {
	Error struct {
		Type   string `json:"type"`
		Reason string `json:"reason"`
	} `json:"error"`
	Status int `json:"status"`
}

type esBulkResponse struct {
	Errors bool             `json:"errors"`
	Items  []esItemResponse `json:"items"`
}

type esItemResponse struct {
	Create esResponse `json:"create"`
}

func NewElasticsearchClient(params types.InitClientArgs) (*Client, error) {
	esCfg := params.Config.Elasticsearch
	endpointUrl := fmt.Sprintf("%s/%s/%s", esCfg.HostPort, esCfg.Index, esCfg.Type)
	c, err := NewClient("Elasticsearch", endpointUrl, esCfg.CommonConfig, params)
	if err != nil {
		return nil, err
	}

	if esCfg.Batching.Enabled {
		log.Printf("[INFO]  : %v - Batching enabled: %v max bytes, %v interval\n", c.OutputType, esCfg.Batching.BatchSize, esCfg.Batching.FlushInterval)
		callbackFn := func(falcoPayloads []types.FalcoPayload, data []byte) {
			go c.elasticsearchPost("", data, falcoPayloads...)
		}
		c.batcher = batcher.New(
			batcher.WithBatchSize(esCfg.Batching.BatchSize),
			batcher.WithFlushInterval(esCfg.Batching.FlushInterval),
			batcher.WithMarshal(c.marshalESBulkPayload),
			batcher.WithCallback(callbackFn),
		)
	}
	if esCfg.EnableCompression {
		c.EnableCompression = true
		log.Printf("[INFO]  : %v - Compression enabled\n", c.OutputType)
	}

	return c, nil
}

func (c *Client) ElasticsearchPost(falcopayload types.FalcoPayload) {
	if c.Config.Elasticsearch.Batching.Enabled {
		c.batcher.Push(falcopayload)
		return
	}

	payload, err := c.marshalESPayload(falcopayload)
	if err != nil {
		log.Printf("[ERROR] : %v - Failed to marshal payload: %v\n", c.OutputType, err)
	}

	c.elasticsearchPost(c.getIndex(), payload, falcopayload)
}

var esReasonMappingFieldsRegex *regexp.Regexp = regexp.MustCompile(`\[\w+(\.\w+)+\]`)

// ElasticsearchPost posts event to Elasticsearch
func (c *Client) elasticsearchPost(index string, payload []byte, falcoPayloads ...types.FalcoPayload) {
	sz := int64(len(falcoPayloads))
	c.Stats.Elasticsearch.Add(Total, sz)

	var eURL string
	if index == "" {
		eURL = c.Config.Elasticsearch.HostPort + "/_bulk"
	} else {
		eURL = c.Config.Elasticsearch.HostPort + "/" + index + "/" + c.Config.Elasticsearch.Type
	}

	endpointURL, err := url.Parse(eURL)
	if err != nil {
		c.setElasticSearchErrorMetrics(sz)
		log.Printf("[ERROR] : %v - %v\n", c.OutputType, err)
		return
	}

	reqOpts := []RequestOptionFunc{
		// Set request headers
		func(req *http.Request) {
			if c.Config.Elasticsearch.ApiKey != "" {
				req.Header.Set("Authorization", "APIKey "+c.Config.Elasticsearch.ApiKey)
			}

			if c.Config.Elasticsearch.Username != "" && c.Config.Elasticsearch.Password != "" {
				req.SetBasicAuth(c.Config.Elasticsearch.Username, c.Config.Elasticsearch.Password)
			}

			for i, j := range c.Config.Elasticsearch.CustomHeaders {
				req.Header.Set(i, j)
			}
		},

		// Set the final endpointURL
		func(req *http.Request) {
			// Append pipeline parameter to the URL if configured
			if c.Config.Elasticsearch.Pipeline != "" {
				query := endpointURL.Query()
				query.Set("pipeline", c.Config.Elasticsearch.Pipeline)
				endpointURL.RawQuery = query.Encode()
			}
			// Set request URL
			req.URL = endpointURL
		},
	}

	var response string
	if c.Config.Elasticsearch.Batching.Enabled {
		// Use PostWithResponse call when batching is enabled in order to capture response body on 200
		res, err := c.PostWithResponse(payload, reqOpts...)
		if err != nil {
			response = err.Error()
		} else {
			response = res
		}
	} else {
		// Use regular Post call, this avoid parsing response on http status 200
		err = c.Post(payload, reqOpts...)
		if err != nil {
			response = err.Error()
		}
	}

	if response != "" {
		if c.Config.Elasticsearch.Batching.Enabled {
			var resp esBulkResponse
			if err2 := json.Unmarshal([]byte(response), &resp); err2 != nil {
				c.setElasticSearchErrorMetrics(sz)
				return
			}
			if len(resp.Items) != len(falcoPayloads) {
				log.Printf("[ERROR] : %v - mismatched %v responses with %v request payloads\n", c.OutputType, len(resp.Items), len(falcoPayloads))
				c.setElasticSearchErrorMetrics(sz)
				return
			}
			// Check errors. Not using the mapping errors retry approach for batched/bulk requests
			// Only mark set the errors and stats
			if resp.Errors {
				failed := int64(0)
				for _, item := range resp.Items {
					switch item.Create.Status {
					case http.StatusOK, http.StatusCreated:
					default:
						failed++
					}
				}
				c.setElasticSearchErrorMetrics(failed)
				// Set success sz that is reported at the end of this function
				sz -= failed
			}
		} else {
			// Slightly refactored the original approach to mapping errors, but logic is still the same
			// The Request is retried only once without the field that can't be mapped.
			// One of the problems with this approach is that if the mapping has two "unmappable" fields
			// only the first one is returned with the error and removed from the retried request.
			// Do we need to retry without the field? Do we need to keep retrying and removing fields until it succeeds?
			var resp esResponse
			if err2 := json.Unmarshal([]byte(response), &resp); err2 != nil {
				c.setElasticSearchErrorMetrics(sz)
				return
			}

			payload := falcoPayloads[0]

			if resp.Error.Type == "document_parsing_exception" {
				k := esReasonMappingFieldsRegex.FindStringSubmatch(resp.Error.Reason)
				if len(k) == 0 {
					c.setElasticSearchErrorMetrics(sz)
					return
				}
				if !strings.Contains(k[0], "output_fields") {
					c.setElasticSearchErrorMetrics(sz)
					return
				}
				s := strings.ReplaceAll(k[0], "[output_fields.", "")
				s = strings.ReplaceAll(s, "]", "")
				for i := range payload.OutputFields {
					if strings.HasPrefix(i, s) {
						delete(payload.OutputFields, i)
					}
				}
				log.Printf("[INFO]  : %v - %v\n", c.OutputType, "attempt to POST again the payload without the wrong field")
				err = c.Post(payload, reqOpts...)
				if err != nil {
					c.setElasticSearchErrorMetrics(sz)
					return
				}
			}
		}
	}

	// Setting the success status
	go c.CountMetric(Outputs, sz, []string{"output:elasticsearch", "status:ok"})
	c.Stats.Elasticsearch.Add(OK, sz)
	c.PromStats.Outputs.With(map[string]string{"destination": "elasticsearch", "status": OK}).Add(float64(sz))
}

func (c *Client) ElasticsearchCreateIndexTemplate(config types.ElasticsearchOutputConfig) error {
	d := c
	indexExists, err := c.isIndexTemplateExist(config)
	if err != nil {
		log.Printf("[ERROR] : %v - %v\n", c.OutputType, err)
		return err
	}
	if indexExists {
		log.Printf("[INFO]  : %v - %v\n", c.OutputType, "Index template already exists")
		return nil
	}

	pattern := "-*"
	if config.Suffix == None {
		pattern = ""
	}
	m := strings.ReplaceAll(ESmapping, "${INDEX}", config.Index)
	m = strings.ReplaceAll(m, "${PATTERN}", pattern)
	m = strings.ReplaceAll(m, "${SHARDS}", fmt.Sprintf("%v", config.NumberOfShards))
	m = strings.ReplaceAll(m, "${REPLICAS}", fmt.Sprintf("%v", config.NumberOfReplicas))
	j := make(map[string]interface{})
	if err := json.Unmarshal([]byte(m), &j); err != nil {
		log.Printf("[ERROR] : %v - %v\n", c.OutputType, err)
		return err
	}
	// create the index template by PUT
	if d.Put(j) != nil {
		log.Printf("[ERROR] : %v - %v\n", c.OutputType, err)
		return err
	}

	log.Printf("[INFO]  : %v - %v\n", c.OutputType, "Index template created")
	return nil
}

func (c *Client) isIndexTemplateExist(config types.ElasticsearchOutputConfig) (bool, error) {
	clientCopy := c
	var err error
	u, err := url.Parse(fmt.Sprintf("%s/_index_template/falco", config.HostPort))
	if err != nil {
		return false, err
	}
	clientCopy.EndpointURL = u
	if err := clientCopy.Get(); err != nil {
		if err.Error() == "resource not found" {
			return false, nil
		}
	}
	return true, nil
}

// setElasticSearchErrorMetrics set the error stats
func (c *Client) setElasticSearchErrorMetrics(n int64) {
	go c.CountMetric(Outputs, n, []string{"output:elasticsearch", "status:error"})
	c.Stats.Elasticsearch.Add(Error, n)
	c.PromStats.Outputs.With(map[string]string{"destination": "elasticsearch", "status": Error}).Add(float64(n))
}

func (c *Client) buildESPayload(falcopayload types.FalcoPayload) eSPayload {
	payload := eSPayload{FalcoPayload: falcopayload, Timestamp: falcopayload.Time}

	if c.Config.Elasticsearch.FlattenFields || c.Config.Elasticsearch.CreateIndexTemplate {
		for i, j := range payload.OutputFields {
			payload.OutputFields[strings.ReplaceAll(i, ".", "_")] = j
			delete(payload.OutputFields, i)
		}
	}
	return payload
}

func (c *Client) marshalESPayload(falcopayload types.FalcoPayload) ([]byte, error) {
	return json.Marshal(c.buildESPayload(falcopayload))
}

func (c *Client) marshalESBulkPayload(falcopayload types.FalcoPayload) ([]byte, error) {
	body, err := c.marshalESPayload(falcopayload)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	_, _ = buf.WriteString(`{"create":{`)
	_, _ = buf.WriteString(`"_index":"`)
	_, _ = buf.WriteString(c.getIndex())
	_, _ = buf.WriteString("\"}}\n")

	_, _ = buf.Write(body)
	_, _ = buf.WriteRune('\n')

	return buf.Bytes(), nil
}

func (c *Client) getIndex() string {
	var index string

	current := time.Now()
	switch c.Config.Elasticsearch.Suffix {
	case None:
		index = c.Config.Elasticsearch.Index
	case "monthly":
		index = c.Config.Elasticsearch.Index + "-" + current.Format("2006.01")
	case "annually":
		index = c.Config.Elasticsearch.Index + "-" + current.Format("2006")
	default:
		index = c.Config.Elasticsearch.Index + "-" + current.Format("2006.01.02")
	}
	return index
}
