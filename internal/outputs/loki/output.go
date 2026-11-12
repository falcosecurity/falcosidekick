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

package loki

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

const (
	name            = "loki"
	defaultEndpoint = "/loki/api/v1/push"
	readyRoute      = "/ready"
)

var targetOptions = shared.HTTPTargetOptions{DefaultEndpoint: defaultEndpoint}

type config struct {
	Tenant      string   `mapstructure:"tenant"`
	Format      string   `mapstructure:"format"`
	LabelFields []string `mapstructure:"label_fields"`
	// labelFields is LabelFields once validated.
	labelFields             []labelField
	shared.HTTPTargetConfig `mapstructure:",squash"`
	shared.HTTPConfig       `mapstructure:",squash"`
	Runtime                 output.RuntimeConfig `mapstructure:"runtime"`
}

// OutputType describes the Loki output for the catalog.
var OutputType = output.Type{
	New:      createOutput,
	Name:     name,
	Category: output.CategoryLogs,
	Schema: output.Schema{
		Fields: append(append(shared.HTTPTargetSchemaFields(&targetOptions), []output.SchemaField{
			{
				Name: "tenant", Type: "string", Label: "Tenant (X-Scope-OrgID)",
				Description: "Tenant ID sent in the `X-Scope-OrgID` header, for a multi-tenant Loki. Empty sends no header.",
			},
			{
				Name: "format", Type: "enum", Values: []string{"json", "text"}, Default: "json", Label: "Log Line Format",
				Description: "Content of each log line: `json` is the whole event as JSON, `text` is the event output text only.",
			},
			{
				Name: "label_fields", Type: "string[]", Label: "Output Fields as Stream Labels",
				Description: "Output field names, such as `container.name`, added as stream labels when the event has them, named with `.` and `[` as `_`: " +
					"`container_name`. Every distinct value adds a stream, so list only fields with few values. " +
					"A name that does not make a valid label name, or makes a built-in label, is refused.",
			},
		}...), append(shared.HTTPConfigSchemaFields(), shared.BatchRuntimeConfigSchemaFields()...)...),
	},
}

type driver struct {
	sender *shared.Sender
	logger *slog.Logger
	cfg    config
}

func (d *driver) RuntimeConfig() output.RuntimeConfig { return d.cfg.Runtime }

var validFormats = map[string]bool{formatJSON: true, "text": true}

func (c *config) validate() utils.ValidationErrors {
	var errs utils.ValidationErrors
	errs.Merge("", c.HTTPConfig.Validate())
	errs.Merge("", c.HTTPTargetConfig.Validate(&targetOptions))
	if c.Format == "" {
		c.Format = formatJSON
	} else if !validFormats[c.Format] {
		errs.Add("format", "must be json/text")
	}
	labelFields, labelErrs := parseLabelFields(c.LabelFields)
	errs.Merge("", labelErrs)
	c.labelFields = labelFields
	if len(errs) > 0 {
		return errs
	}
	return nil
}

func createOutput(raw map[string]any, deps output.Deps) (output.Driver, error) {
	var cfg config
	if err := shared.DecodeDriverConfig(raw, &cfg); err != nil {
		return nil, fmt.Errorf("%s config: %w", name, err)
	}
	if errs := cfg.validate(); len(errs) > 0 {
		return nil, fmt.Errorf("%s: %w", name, errs)
	}

	sender, err := shared.NewSender(name, &cfg.HTTPConfig)
	if err != nil {
		return nil, err
	}
	if cfg.Tenant != "" {
		sender.SetHeader("X-Scope-OrgID", cfg.Tenant)
	}

	return &driver{
		cfg:    cfg,
		sender: sender,
		logger: shared.ResolveLogger(deps.Logger, name),
	}, nil
}

func (d *driver) Name() string { return name }

func (d *driver) Init(_ context.Context) error { return nil }

func (d *driver) Send(ctx context.Context, evt *event.Event) error {
	target, err := d.cfg.DeliveryURL()
	if err != nil {
		return shared.WrapDeliveryError(name, shared.OpTarget, err)
	}
	payload := buildPayload(d.cfg.Format, d.cfg.labelFields, evt)
	return d.sender.SendGzipJSON(ctx, http.MethodPost, target, payload)
}

func (d *driver) SendBatch(ctx context.Context, events []*event.Event) error {
	target, err := d.cfg.DeliveryURL()
	if err != nil {
		return shared.WrapDeliveryError(name, shared.OpTarget, err)
	}
	payload := buildBatchPayload(d.cfg.Format, d.cfg.labelFields, events)
	return d.sender.SendGzipJSON(ctx, http.MethodPost, target, payload)
}

func (d *driver) HealthCheck(ctx context.Context) error {
	target, err := d.cfg.URL(d.cfg.Host, readyRoute, nil)
	if err != nil {
		return shared.WrapDeliveryError(name, shared.OpTarget, err)
	}
	return d.sender.HealthCheck(ctx, target)
}

func (d *driver) Close() error {
	d.sender.Close()
	return nil
}
