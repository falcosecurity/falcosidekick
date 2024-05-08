// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/falcosecurity/falcosidekick/types"
	"github.com/google/uuid"
)

const Falcosidekick_ string = "falcosidekick_"
const SourcePath string = "/source/"
const APIv1Path string = "api/v1/org/"

func isSourcePresent(config *types.Configuration) (bool, error) {

	client := &http.Client{}

	source_url, err := url.JoinPath(config.Spyderbat.APIUrl, APIv1Path+config.Spyderbat.OrgUID+SourcePath)
	if err != nil {
		return false, err
	}
	req, err := http.NewRequest("GET", source_url, new(bytes.Buffer))
	if err != nil {
		return false, err
	}
	req.Header.Add("Authorization", Bearer+" "+config.Spyderbat.APIKey)

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	if resp.StatusCode != http.StatusOK {
		return false, errors.New("HTTP error: " + resp.Status)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}
	var sources []map[string]interface{}
	if err := json.Unmarshal(body, &sources); err != nil {
		return false, err
	}
	uid := Falcosidekick_ + config.Spyderbat.OrgUID
	for _, source := range sources {
		if id, ok := source["uid"]; ok && id.(string) == uid {
			return true, nil
		}
	}
	return false, nil
}

type SourceBody struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	UID         string `json:"uid"`
}

func makeSource(config *types.Configuration) error {

	data := SourceBody{
		Name:        config.Spyderbat.Source,
		Description: config.Spyderbat.SourceDescription,
		UID:         Falcosidekick_ + config.Spyderbat.OrgUID,
	}
	body := new(bytes.Buffer)
	if err := json.NewEncoder(body).Encode(data); err != nil {
		return err
	}

	client := &http.Client{}

	source_url, err := url.JoinPath(config.Spyderbat.APIUrl, APIv1Path+config.Spyderbat.OrgUID+SourcePath)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", source_url, body)
	if err != nil {
		return err
	}
	req.Header.Add("Authorization", Bearer+" "+config.Spyderbat.APIKey)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusBadRequest {
			if b, err := io.ReadAll(resp.Body); err == nil {
				return errors.New("Bad request: " + string(b))
			}
		}
		return errors.New("HTTP error: " + resp.Status)
	}
	defer resp.Body.Close()

	return nil
}

const Schema = "falco_alert::1.0.0"

var PriorityMap = map[types.PriorityType]string{
	types.Emergency:     "critical",
	types.Alert:         "high",
	types.Critical:      "critical",
	types.Error:         "high",
	types.Warning:       "medium",
	types.Notice:        "low",
	types.Informational: "info",
	types.Debug:         "info",
}

type spyderbatPayload struct {
	Schema        string   `json:"schema"`
	ID            string   `json:"id"`
	MonotonicTime int      `json:"monotonic_time"`
	OrcTime       float64  `json:"orc_time"`
	Time          float64  `json:"time"`
	PID           int32    `json:"pid"`
	Level         string   `json:"level"`
	Message       []string `json:"msg"`
	Arguments     string   `json:"args"`
	Container     string   `json:"container"`
}

func newSpyderbatPayload(falcopayload types.FalcoPayload) (spyderbatPayload, error) {
	nowTime := float64(time.Now().UnixNano()) / 1000000000

	timeStr := falcopayload.OutputFields["evt.time"]
	if timeStr == nil {
		errStr := fmt.Sprintf("evt.time is nil for rule %s", falcopayload.Rule)
		return spyderbatPayload{}, errors.New(errStr)
	}
	jsonTime, err := timeStr.(json.Number).Int64()
	if err != nil {
		return spyderbatPayload{}, err
	}
	eventTime := float64(jsonTime / 1000000000.0)

	pidStr := falcopayload.OutputFields["proc.pid"]
	if pidStr == nil {
		errStr := fmt.Sprintf("proc.pid is nil for rule %s", falcopayload.Rule)
		return spyderbatPayload{}, errors.New(errStr)
	}
	pid, err := pidStr.(json.Number).Int64()
	if err != nil {
		return spyderbatPayload{}, err
	}

	level := PriorityMap[falcopayload.Priority]
	args := strings.Split(falcopayload.Output, " ")
	var message []string
	if len(args) > 2 {
		message = args[2:]
	}
	arguments := falcopayload.OutputFields["proc.cmdline"].(string)
	container := falcopayload.OutputFields["container.id"].(string)

	return spyderbatPayload{
		Schema:        Schema,
		ID:            uuid.NewString(),
		MonotonicTime: time.Now().Nanosecond(),
		OrcTime:       nowTime,
		Time:          eventTime,
		PID:           int32(pid),
		Level:         level,
		Message:       message,
		Arguments:     arguments,
		Container:     container,
	}, nil
}

func NewSpyderbatClient(config *types.Configuration, stats *types.Statistics, promStats *types.PromStatistics,
	statsdClient, dogstatsdClient *statsd.Client) (*Client, error) {

	hasSource, err := isSourcePresent(config)
	if err != nil {
		log.Printf("[ERROR] : Spyderbat - %v\n", err.Error())
		return nil, ErrClientCreation
	}
	if !hasSource {
		if err := makeSource(config); err != nil {
			if hasSource, err2 := isSourcePresent(config); err2 != nil || !hasSource {
				log.Printf("[ERROR] : Spyderbat - %v\n", err.Error())
				return nil, ErrClientCreation
			}
		}
	}

	source := Falcosidekick_ + config.Spyderbat.OrgUID
	data_url, err := url.JoinPath(config.Spyderbat.APIUrl, APIv1Path+config.Spyderbat.OrgUID+SourcePath+source+"/data/sb-agent")
	if err != nil {
		log.Printf("[ERROR] : Spyderbat - %v\n", err.Error())
		return nil, ErrClientCreation
	}
	endpointURL, err := url.Parse(data_url)
	if err != nil {
		log.Printf("[ERROR] : Spyderbat - %v\n", err.Error())
		return nil, ErrClientCreation
	}
	return &Client{
		OutputType:       "Spyderbat",
		EndpointURL:      endpointURL,
		MutualTLSEnabled: false,
		CheckCert:        true,
		ContentType:      "application/ndjson",
		Config:           config,
		Stats:            stats,
		PromStats:        promStats,
		StatsdClient:     statsdClient,
		DogstatsdClient:  dogstatsdClient,
	}, nil
}

func (c *Client) SpyderbatPost(falcopayload types.FalcoPayload) {
	c.Stats.Spyderbat.Add(Total, 1)

	c.httpClientLock.Lock()
	defer c.httpClientLock.Unlock()
	c.AddHeader("Authorization", "Bearer "+c.Config.Spyderbat.APIKey)
	c.AddHeader("Content-Encoding", "gzip")

	payload, err := newSpyderbatPayload(falcopayload)
	if err == nil {
		err = c.Post(payload)
	}
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:spyderbat", "status:error"})
		c.Stats.Spyderbat.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "spyderbat", "status": Error}).Inc()
		log.Printf("[ERROR] : Spyderbat - %v\n", err.Error())
		return
	}

	go c.CountMetric(Outputs, 1, []string{"output:spyderbat", "status:ok"})
	c.Stats.Spyderbat.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "spyderbat", "status": OK}).Inc()
}
