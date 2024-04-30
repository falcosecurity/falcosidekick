// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/falcosecurity/falcosidekick/types"
)

type eSPayload struct {
	types.FalcoPayload
	Timestamp time.Time `json:"@timestamp"`
}

type mappingError struct {
	Error struct {
		RootCause []struct {
			Type   string `json:"type"`
			Reason string `json:"reason"`
		} `json:"root_cause"`
		Type   string `json:"type"`
		Reason string `json:"reason"`
	} `json:"error"`
	Status int `json:"status"`
}

// ElasticsearchPost posts event to Elasticsearch
func (c *Client) ElasticsearchPost(falcopayload types.FalcoPayload) {
	c.Stats.Elasticsearch.Add(Total, 1)

	current := time.Now()
	var eURL string
	switch c.Config.Elasticsearch.Suffix {
	case None:
		eURL = c.Config.Elasticsearch.HostPort + "/" + c.Config.Elasticsearch.Index + "/" + c.Config.Elasticsearch.Type
	case "monthly":
		eURL = c.Config.Elasticsearch.HostPort + "/" + c.Config.Elasticsearch.Index + "-" + current.Format("2006.01") + "/" + c.Config.Elasticsearch.Type
	case "annually":
		eURL = c.Config.Elasticsearch.HostPort + "/" + c.Config.Elasticsearch.Index + "-" + current.Format("2006") + "/" + c.Config.Elasticsearch.Type
	default:
		eURL = c.Config.Elasticsearch.HostPort + "/" + c.Config.Elasticsearch.Index + "-" + current.Format("2006.01.02") + "/" + c.Config.Elasticsearch.Type
	}

	endpointURL, err := url.Parse(eURL)
	if err != nil {
		c.setElasticSearchErrorMetrics()
		log.Printf("[ERROR] : %v - %v\n", c.OutputType, err.Error())
		return
	}

	c.EndpointURL = endpointURL
	if c.Config.Elasticsearch.Username != "" && c.Config.Elasticsearch.Password != "" {
		c.httpClientLock.Lock()
		defer c.httpClientLock.Unlock()
		c.BasicAuth(c.Config.Elasticsearch.Username, c.Config.Elasticsearch.Password)
	}

	for i, j := range c.Config.Elasticsearch.CustomHeaders {
		c.AddHeader(i, j)
	}

	payload := eSPayload{FalcoPayload: falcopayload, Timestamp: falcopayload.Time}
	if c.Config.Elasticsearch.FlattenFields || c.Config.Elasticsearch.CreateIndexTemplate {
		for i, j := range payload.OutputFields {
			payload.OutputFields[strings.ReplaceAll(i, ".", "_")] = j
			delete(payload.OutputFields, i)
		}
	}

	err = c.Post(payload)
	if err != nil {
		var mappingErr mappingError
		if err2 := json.Unmarshal([]byte(err.Error()), &mappingErr); err2 != nil {
			c.setElasticSearchErrorMetrics()
			return
		}
		if mappingErr.Error.Type == "document_parsing_exception" {
			reg := regexp.MustCompile(`\[\w+(\.\w+)+\]`)
			k := reg.FindStringSubmatch(mappingErr.Error.Reason)
			if len(k) == 0 {
				c.setElasticSearchErrorMetrics()
				return
			}
			if !strings.Contains(k[0], "output_fields") {
				c.setElasticSearchErrorMetrics()
				return
			}
			s := strings.ReplaceAll(k[0], "[output_fields.", "")
			s = strings.ReplaceAll(s, "]", "")
			for i := range payload.OutputFields {
				if strings.HasPrefix(i, s) {
					delete(payload.OutputFields, i)
				}
			}
			fmt.Println(payload.OutputFields)
			log.Printf("[INFO]  : %v - %v\n", c.OutputType, "attempt to POST again the payload without the wrong field")
			err = c.Post(payload)
			if err != nil {
				c.setElasticSearchErrorMetrics()
				return
			}
		}
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:elasticsearch", "status:ok"})
	c.Stats.Elasticsearch.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "elasticsearch", "status": OK}).Inc()
}

func (c *Client) ElasticsearchCreateIndexTemplate(config types.ElasticsearchOutputConfig) error {
	d := c
	var err error
	u, err := url.Parse(fmt.Sprintf("%s/_index_template/falco", config.HostPort))
	if err != nil {
		log.Printf("[ERROR] : %v - %v\n", c.OutputType, err.Error())
		return err
	}
	d.EndpointURL = u
	if err := d.Get(); err != nil {
		if err.Error() == "resource not found" {
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
				log.Printf("[ERROR] : %v - %v\n", c.OutputType, err.Error())
				return err
			}
			if d.Put(j) != nil {
				log.Printf("[ERROR] : %v - %v\n", c.OutputType, err.Error())
				return err
			}
			log.Printf("[INFO]  : %v - %v\n", c.OutputType, "Index template created")
		} else {
			log.Printf("[ERROR] : %v - %v\n", c.OutputType, err.Error())
			return err
		}
	} else {
		log.Printf("[INFO]  : %v - %v\n", c.OutputType, "Index template already exists")
	}
	return nil
}

// setElasticSearchErrorMetrics set the error stats
func (c *Client) setElasticSearchErrorMetrics() {
	go c.CountMetric(Outputs, 1, []string{"output:elasticsearch", "status:error"})
	c.Stats.Elasticsearch.Add(Error, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "elasticsearch", "status": Error}).Inc()
}
