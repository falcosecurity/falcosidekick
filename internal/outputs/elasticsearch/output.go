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
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

const (
	name             = "elasticsearch"
	opTemplateCheck  = "index template check"
	opTemplateCreate = "index template create"
	defaultIndex     = "falco"
	defaultSuffix    = "daily"
	suffixNone       = "none"
	defaultShards    = 3
	defaultReplicas  = 3

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
	Name:     name,
	Category: output.CategoryLogs,
	Schema: output.Schema{
		Fields: append(append(shared.HTTPTargetSchemaFields(&targetOptions), []output.SchemaField{
			{
				Name: "index", Type: "string", Default: "falco", Label: "Index",
				Description: "Index the events are written to, before the date suffix: lowercase letters, digits, `.`, `-` and `_`, starting with a letter or digit.",
			},
			{
				Name: "index_suffix", Type: "enum", Values: []string{"daily", "monthly", "annually", suffixNone}, Default: "daily", Label: "Index Suffix",
				Description: "Date added to the index at delivery time, in UTC: `-YYYY.MM.DD`, `-YYYY.MM` or `-YYYY`. `none` writes to the index itself.",
			},
			{
				Name: "pipeline", Type: "string", Label: "Ingest Pipeline",
				Description: "Ingest pipeline every document goes through, sent as the `pipeline` query parameter. Empty uses the index default.",
			},
			{
				Name: "api_key", Type: "string", Secret: true, Label: "API Key",
				Description: "Elasticsearch API key in its encoded form, sent as `Authorization: ApiKey <key>`.",
			},
			{
				Name: "flatten_fields", Type: "bool", Default: false, Label: "Flatten Fields",
				Description: "Replaces `.` with `_` in output field names, such as `proc_name`, so they are stored as flat fields instead of nested objects.",
			},
			{
				Name: "create_index_template", Type: "bool", Default: false, Label: "Create Index Template",
				Description: "Creates an index template named after the index, with the shard and replica counts and the event mappings, before the first delivery. " +
					"An existing template is left unchanged.",
			},
			{
				Name: "number_of_shards", Type: "int", Default: defaultShards, Label: "Number of Shards",
				Description: "Primary shards of each new index, set in the created template; must be greater than `0`. Used only when the template is created.",
			},
			{
				Name: "number_of_replicas", Type: "int", Default: defaultReplicas, Label: "Number of Replicas",
				Description: "Replicas of each primary shard, set in the created template; `0` keeps no replica. Used only when the template is created.",
			},
		}...), append(shared.HTTPConfigSchemaFields(), shared.BatchRuntimeConfigSchemaFields()...)...),
	},
}

type driver struct {
	sender *shared.Sender
	logger *slog.Logger
	// templateGate admits one template check at a time; a waiting delivery leaves when its context ends.
	templateGate  *semaphore.Weighted
	cfg           config
	templateReady atomic.Bool
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
		errs.Add("index", "must be lowercase alphanumeric (a-z, 0-9, ., -, _), cannot start with -, _, +")
	}
	if c.Suffix == "" {
		c.Suffix = defaultSuffix
	} else if !validSuffixes[c.Suffix] {
		errs.Add("index_suffix", "must be daily/monthly/annually/none")
	}
	if c.CreateIndexTemplate {
		if c.NumberOfShards <= 0 {
			errs.Add("number_of_shards", "must be > 0 when create_index_template is true")
		}
		if c.NumberOfReplicas < 0 {
			errs.Add("number_of_replicas", "must be >= 0 when create_index_template is true")
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
		return nil, fmt.Errorf("%s config: %w", name, err)
	}
	if errs := cfg.validate(); len(errs) > 0 {
		return nil, fmt.Errorf("%s: %s", name, errs.Error())
	}

	sender, err := shared.NewSender(name, &cfg.HTTPConfig)
	if err != nil {
		return nil, err
	}
	if cfg.APIKey != "" {
		sender.SetHeader("Authorization", "ApiKey "+cfg.APIKey)
	}

	return &driver{
		sender:       sender,
		logger:       shared.ResolveLogger(deps.Logger, name),
		templateGate: semaphore.NewWeighted(1),
		cfg:          cfg,
	}, nil
}

func (d *driver) Name() string { return name }

// Init fails only on a misconfiguration; otherwise the first delivery retries the template.
func (d *driver) Init(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, templateInitTimeout)
	defer cancel()
	err := d.ensureTemplate(ctx)
	if err == nil || errors.Is(err, output.ErrMisconfigured) {
		return err
	}
	d.logger.Warn("index template not created yet, retried before the first delivery", "error", err)
	return nil
}

const templateInitTimeout = 5 * time.Second

// ensureTemplate blocks deliveries: an index created without the template keeps the wrong mapping.
func (d *driver) ensureTemplate(ctx context.Context) error {
	if !d.cfg.CreateIndexTemplate || d.templateReady.Load() {
		return nil
	}
	if err := d.templateGate.Acquire(ctx, 1); err != nil {
		return shared.WrapDeliveryError(name, opTemplateCheck, err)
	}
	defer d.templateGate.Release(1)
	if d.templateReady.Load() {
		return nil
	}
	if err := d.createIndexTemplate(ctx); err != nil {
		return shared.ClassifyMisconfiguration(err)
	}
	d.templateReady.Store(true)
	return nil
}

// Send uses _create with the event UUID so a retry of an indexed event is a no-op.
func (d *driver) Send(ctx context.Context, evt *event.Event) error {
	if err := d.ensureTemplate(ctx); err != nil {
		return err
	}
	body, err := d.marshalEvent(evt)
	if err != nil {
		return shared.WrapDeliveryError(name, shared.OpMarshal, err)
	}

	index := d.resolveIndex(evt)
	method, route := http.MethodPost, "/"+index+"/_doc"
	if evt.UUID != "" {
		method, route = http.MethodPut, "/"+index+"/_create/"+url.PathEscape(evt.UUID)
	}
	target, err := d.cfg.URL(d.cfg.Host, route, d.pipelineQuery())
	if err != nil {
		return shared.WrapDeliveryError(name, shared.OpTarget, err)
	}

	err = d.sender.SendRaw(ctx, method, target, body, "application/json")
	if evt.UUID != "" && shared.HTTPStatus(err) == http.StatusConflict {
		d.logger.Debug("event already indexed")
		return nil
	}
	return err
}

func (d *driver) SendBatch(ctx context.Context, events []*event.Event) error {
	if err := d.ensureTemplate(ctx); err != nil {
		return err
	}
	body, err := d.buildBulkBody(events)
	if err != nil {
		return err
	}

	query := d.pipelineQuery()
	query.Set(queryFilterPath, bulkFilterPath)
	target, err := d.cfg.URL(d.cfg.Host, "/_bulk", query)
	if err != nil {
		return shared.WrapDeliveryError(name, shared.OpTarget, err)
	}

	respBody, err := d.sender.SendRawReadBody(ctx, http.MethodPost, target, body, "application/json")
	if err != nil {
		return err
	}

	return d.parseBulkResponse(respBody, len(events))
}

func (d *driver) HealthCheck(ctx context.Context) error {
	target, err := d.cfg.URL(d.cfg.Host, "", nil)
	if err != nil {
		return shared.WrapDeliveryError(name, shared.OpTarget, err)
	}
	// GET / needs the cluster monitor privilege an index-only user can lack, so 403 is transient.
	return d.sender.HealthCheck(ctx, target, http.StatusForbidden)
}

func (d *driver) Close() error {
	d.sender.Close()
	return nil
}

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

// resolveIndex dates the index from the event time, in UTC, so a retry or a queued event lands in the
// index of the day it happened, like its @timestamp.
func (d *driver) resolveIndex(evt *event.Event) string {
	t := evt.Time
	if t.IsZero() {
		t = time.Now()
	}
	t = t.UTC()
	switch d.cfg.Suffix {
	case "monthly":
		return fmt.Sprintf("%s-%s", d.cfg.Index, t.Format("2006.01"))
	case "annually":
		return fmt.Sprintf("%s-%s", d.cfg.Index, t.Format("2006"))
	case suffixNone:
		return d.cfg.Index
	default:
		return fmt.Sprintf("%s-%s", d.cfg.Index, t.Format("2006.01.02"))
	}
}
