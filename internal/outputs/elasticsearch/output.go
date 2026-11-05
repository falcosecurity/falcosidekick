// Copyright (C) 2026 The Falco Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package elasticsearch

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

const (
	defaultIndex    = "falco"
	defaultSuffix   = "daily"
	suffixNone      = "none"
	defaultShards   = 3
	defaultReplicas = 3

	queryFilterPath = "filter_path"
	queryPipeline   = "pipeline"
)

var targetOptions = shared.HTTPTargetOptions{
	DriverRoutes:        true,
	ReservedQueryParams: []string{queryFilterPath, queryPipeline},
}

type config struct {
	Index                   string `mapstructure:"index"`
	Suffix                  string `mapstructure:"index_suffix"`
	Pipeline                string `mapstructure:"pipeline"`
	APIKey                  string `mapstructure:"api_key"`
	shared.HTTPTargetConfig `mapstructure:",squash"`
	shared.HTTPConfig       `mapstructure:",squash"`
	Runtime                 output.RuntimeConfig `mapstructure:"runtime"`
	NumberOfShards          int                  `mapstructure:"number_of_shards"`
	NumberOfReplicas        int                  `mapstructure:"number_of_replicas"`
	FlattenFields           bool                 `mapstructure:"flatten_fields"`
	CreateIndexTemplate     bool                 `mapstructure:"create_index_template"`
}

// OutputType describes the Elasticsearch output for the catalog.
var OutputType = output.Type{
	New:      createOutput,
	Name:     "elasticsearch",
	Category: "logs",
	Schema: output.Schema{
		Fields: append(append(shared.HTTPTargetSchemaFields(&targetOptions), []output.SchemaField{
			{Name: "index", Type: "string", Default: "falco", Label: "Index"},
			{Name: "index_suffix", Type: "enum", Values: []string{"daily", "monthly", "annually", suffixNone}, Default: "daily", Label: "Index Suffix"},
			{Name: "pipeline", Type: "string", Label: "Ingest Pipeline"},
			{Name: "api_key", Type: "string", Secret: true, Label: "API Key"},
			{Name: "flatten_fields", Type: "bool", Default: false, Label: "Flatten Fields"},
			{Name: "create_index_template", Type: "bool", Default: false, Label: "Create Index Template"},
			{Name: "number_of_shards", Type: "int", Default: defaultShards, Label: "Number of Shards"},
			{Name: "number_of_replicas", Type: "int", Default: defaultReplicas, Label: "Number of Replicas"},
		}...), append(shared.HTTPConfigSchemaFields(), shared.RuntimeConfigSchemaFields()...)...),
	},
}

type driver struct {
	sender *shared.Sender
	logger *slog.Logger
	cfg    config
}

func (d *driver) RuntimeConfig() output.RuntimeConfig { return d.cfg.Runtime }

var (
	validSuffixes = map[string]bool{"daily": true, "monthly": true, "annually": true, suffixNone: true}
	indexRegex    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)
)

func (c *config) validate() utils.ValidationErrors {
	var errs utils.ValidationErrors
	errs.Merge("", c.HTTPConfig.Validate())
	errs.Merge("", c.HTTPTargetConfig.Validate(&targetOptions))
	if c.Index == "" {
		c.Index = defaultIndex
	} else if !indexRegex.MatchString(c.Index) {
		errs.Add("index", fmt.Sprintf("must be lowercase alphanumeric (a-z, 0-9, ., -, _), cannot start with -, _, +; got %q", c.Index))
	}
	if c.Suffix == "" {
		c.Suffix = defaultSuffix
	} else if !validSuffixes[c.Suffix] {
		errs.Add("index_suffix", fmt.Sprintf("must be daily/monthly/annually/none, got %q", c.Suffix))
	}
	if c.CreateIndexTemplate {
		if c.NumberOfShards <= 0 {
			errs.Add("number_of_shards", fmt.Sprintf("must be > 0 when create_index_template is true, got %d", c.NumberOfShards))
		}
		if c.NumberOfReplicas < 0 {
			errs.Add("number_of_replicas", fmt.Sprintf("must be >= 0 when create_index_template is true, got %d", c.NumberOfReplicas))
		}
	}
	errs.Merge("", c.ValidateCredential(shared.CredentialHeader{Field: "api_key", Header: "Authorization"}, c.APIKey))
	if len(errs) > 0 {
		return errs
	}
	return nil
}

func createOutput(raw map[string]any, deps output.Deps) (output.Driver, error) {
	// Absent keys keep these defaults; explicit values, including 0, replace them.
	cfg := config{NumberOfShards: defaultShards, NumberOfReplicas: defaultReplicas}
	if err := shared.DecodeDriverConfig(raw, &cfg); err != nil {
		return nil, fmt.Errorf("elasticsearch config: %w", err)
	}
	if errs := cfg.validate(); len(errs) > 0 {
		return nil, fmt.Errorf("elasticsearch: %s", errs.Error())
	}

	sender, err := shared.NewSender("elasticsearch", &cfg.HTTPConfig)
	if err != nil {
		return nil, err
	}
	if cfg.APIKey != "" {
		sender.SetHeader("Authorization", "ApiKey "+cfg.APIKey)
	}

	return &driver{
		sender: sender,
		logger: shared.ResolveLogger(deps.Logger, "elasticsearch"),
		cfg:    cfg,
	}, nil
}

func (d *driver) Name() string { return "elasticsearch" }

// Init creates the index template if configured.
func (d *driver) Init(ctx context.Context) error {
	if d.cfg.CreateIndexTemplate {
		return d.createIndexTemplate(ctx)
	}
	return nil
}

// Send delivers a single event to Elasticsearch.
// With a UUID it uses the _create API, so a retry of an indexed event is a no-op.
func (d *driver) Send(ctx context.Context, evt *event.Event) error {
	body, err := d.marshalEvent(evt)
	if err != nil {
		return shared.WrapDeliveryError("elasticsearch", "marshal", err)
	}

	method, route := http.MethodPost, "/"+d.resolveIndex()+"/_doc"
	if evt.UUID != "" {
		method, route = http.MethodPut, "/"+d.resolveIndex()+"/_create/"+url.PathEscape(evt.UUID)
	}
	target, err := d.cfg.URL(d.cfg.Host, route, d.pipelineQuery())
	if err != nil {
		return shared.WrapDeliveryError("elasticsearch", "target", err)
	}

	err = d.sender.SendRaw(ctx, method, target, body, "application/json")
	if evt.UUID != "" && shared.HTTPStatus(err) == http.StatusConflict {
		d.logger.Debug("event already indexed")
		return nil
	}
	return err
}

// SendBatch delivers multiple events using the Elasticsearch bulk API.
// Any failed item fails the batch; items already indexed by an earlier
// attempt are reported as conflicts and count as delivered.
func (d *driver) SendBatch(ctx context.Context, events []*event.Event) error {
	body, err := d.buildBulkBody(events)
	if err != nil {
		return err
	}

	query := d.pipelineQuery()
	query.Set(queryFilterPath, bulkFilterPath)
	target, err := d.cfg.URL(d.cfg.Host, "/_bulk", query)
	if err != nil {
		return shared.WrapDeliveryError("elasticsearch", "target", err)
	}

	respBody, err := d.sender.SendRawReadBody(ctx, http.MethodPost, target, body, "application/json")
	if err != nil {
		return err
	}

	return d.parseBulkResponse(respBody, len(events))
}

// HealthCheck verifies connectivity to Elasticsearch.
func (d *driver) HealthCheck(ctx context.Context) error {
	target, err := d.cfg.URL(d.cfg.Host, "", nil)
	if err != nil {
		return shared.WrapDeliveryError("elasticsearch", "target", err)
	}
	// GET / needs the cluster monitor privilege, which a user that may only
	// index can lack, so 403 is not proof of a wrong configuration.
	return d.sender.HealthCheck(ctx, target, http.StatusForbidden)
}

func (d *driver) Close() error { return nil }

func (d *driver) pipelineQuery() url.Values {
	query := url.Values{}
	if d.cfg.Pipeline != "" {
		query.Set(queryPipeline, d.cfg.Pipeline)
	}
	return query
}

func (d *driver) marshalEvent(evt *event.Event) ([]byte, error) {
	fields := evt.OutputFields
	if d.cfg.FlattenFields {
		fields = make(map[string]interface{}, len(evt.OutputFields))
		for k, v := range evt.OutputFields {
			fields[strings.ReplaceAll(k, ".", "_")] = v
		}
	}

	type alias event.Event
	tmp := struct {
		*alias
		OutputFields map[string]interface{} `json:"output_fields"`
		Timestamp    string                 `json:"@timestamp"`
	}{
		alias:        (*alias)(evt),
		OutputFields: fields,
		Timestamp:    evt.Time.Format(time.RFC3339Nano),
	}

	return json.Marshal(tmp)
}

func (d *driver) resolveIndex() string {
	switch d.cfg.Suffix {
	case "monthly":
		return fmt.Sprintf("%s-%s", d.cfg.Index, time.Now().Format("2006.01"))
	case "annually":
		return fmt.Sprintf("%s-%s", d.cfg.Index, time.Now().Format("2006"))
	case suffixNone:
		return d.cfg.Index
	default:
		return fmt.Sprintf("%s-%s", d.cfg.Index, time.Now().Format("2006.01.02"))
	}
}
