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
	"strings"

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
	Tenant                  string `mapstructure:"tenant"`
	LogFormat               string `mapstructure:"log_format"`
	ExtraLabels             string `mapstructure:"extra_labels"`
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
				Name: "log_format", Type: "enum", Values: []string{"json", "text"}, Default: "json", Label: "Log Format",
				Description: "Content of each log line: `json` is the whole event as JSON, `text` is the event output text only.",
			},
			{
				Name: "extra_labels", Type: "string", Label: "Extra Labels (comma-separated field names)",
				Description: "Output field names, separated by commas, such as `container.id,proc.name`, added as stream labels when the event has them. " +
					"Characters other than letters, digits and `_` in label names become `_`.",
			},
		}...), append(shared.HTTPConfigSchemaFields(), shared.BatchRuntimeConfigSchemaFields()...)...),
	},
}

type driver struct {
	sender      *shared.Sender
	logger      *slog.Logger
	extraLabels []string
	cfg         config
}

func (d *driver) RuntimeConfig() output.RuntimeConfig { return d.cfg.Runtime }

var validLogFormats = map[string]bool{formatJSON: true, "text": true}

func (c *config) validate() utils.ValidationErrors {
	var errs utils.ValidationErrors
	errs.Merge("", c.HTTPConfig.Validate())
	errs.Merge("", c.HTTPTargetConfig.Validate(&targetOptions))
	if c.LogFormat == "" {
		c.LogFormat = formatJSON
	} else if !validLogFormats[c.LogFormat] {
		errs.Add("log_format", "must be json/text")
	}
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
		return nil, fmt.Errorf("%s: %s", name, errs.Error())
	}

	sender, err := shared.NewSender(name, &cfg.HTTPConfig)
	if err != nil {
		return nil, err
	}
	if cfg.Tenant != "" {
		sender.SetHeader("X-Scope-OrgID", cfg.Tenant)
	}

	var extraLabels []string
	if cfg.ExtraLabels != "" {
		for _, l := range strings.Split(cfg.ExtraLabels, ",") {
			l = strings.TrimSpace(l)
			if l != "" {
				extraLabels = append(extraLabels, l)
			}
		}
	}

	return &driver{
		cfg:         cfg,
		sender:      sender,
		logger:      shared.ResolveLogger(deps.Logger, name),
		extraLabels: extraLabels,
	}, nil
}

func (d *driver) Name() string { return name }

func (d *driver) Init(_ context.Context) error { return nil }

func (d *driver) Send(ctx context.Context, evt *event.Event) error {
	target, err := d.cfg.DeliveryURL()
	if err != nil {
		return shared.WrapDeliveryError(name, shared.OpTarget, err)
	}
	payload := buildPayload(d.cfg.LogFormat, d.extraLabels, evt)
	return d.sender.SendGzipJSON(ctx, http.MethodPost, target, payload)
}

func (d *driver) SendBatch(ctx context.Context, events []*event.Event) error {
	target, err := d.cfg.DeliveryURL()
	if err != nil {
		return shared.WrapDeliveryError(name, shared.OpTarget, err)
	}
	payload := buildBatchPayload(d.cfg.LogFormat, d.extraLabels, events)
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
