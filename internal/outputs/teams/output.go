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

package teams

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
	name         = "teams"
	formatAll    = "all"
	formatFields = "fields"
	formatText   = "text"
	// signatureParam is the Workflows trigger query parameter that authorizes the call.
	signatureParam = "sig"
)

// Workflows URLs vary per tenant and region, so host has no default.
var targetOptions = shared.HTTPTargetOptions{SecretEndpointRequired: true}

type config struct {
	IconURL                 string `mapstructure:"icon_url"`
	OutputFormat            string `mapstructure:"output_format"`
	shared.HTTPTargetConfig `mapstructure:",squash"`
	shared.HTTPConfig       `mapstructure:",squash"`
	Runtime                 output.RuntimeConfig `mapstructure:"runtime"`
}

// OutputType describes the Microsoft Teams output for the catalog.
var OutputType = output.Type{
	New:      createOutput,
	Name:     name,
	Category: output.CategoryChat,
	Schema: output.Schema{
		Fields: append(append(shared.HTTPTargetSchemaFields(&targetOptions), []output.SchemaField{
			{
				Name: "icon_url", Type: "string", Suggested: shared.FalcosidekickIconURL, Label: "Icon URL",
				Description: "Absolute http or https URL of the image shown beside the card heading. Empty shows no image.",
			},
			{
				Name: "output_format", Type: "enum", Values: []string{formatAll, formatText, formatFields}, Default: formatAll, Label: "Output Format",
				Description: "Content of the card: `text` is the event output text, `fields` lists rule, priority, source, hostname, output fields and tags, `all` shows both.",
			},
		}...), append(shared.HTTPConfigSchemaFields(), shared.RuntimeConfigSchemaFields()...)...),
	},
}

type driver struct {
	sender *shared.Sender
	logger *slog.Logger
	cfg    config
}

var validOutputFormats = map[string]bool{formatAll: true, formatFields: true, formatText: true}

func (c *config) validate() utils.ValidationErrors {
	var errs utils.ValidationErrors
	errs.Merge("", c.HTTPConfig.Validate())
	errs.Merge("", c.HTTPTargetConfig.Validate(&targetOptions))
	if sig, ok := c.QueryParams[signatureParam]; ok && len(sig.Values) > 0 {
		errs.Add(fmt.Sprintf("query_params[%q]", signatureParam), "is a credential; use secrets or files")
	}
	if c.OutputFormat == "" {
		c.OutputFormat = formatAll
	} else if !validOutputFormats[c.OutputFormat] {
		errs.Add("output_format", "must be all/text/fields")
	}
	if c.IconURL != "" && !shared.IsAbsoluteHTTPURL(c.IconURL) {
		errs.Add("icon_url", "must be an absolute http or https URL")
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
	return &driver{cfg: cfg, sender: sender, logger: shared.ResolveLogger(deps.Logger, name)}, nil
}

func (d *driver) Name() string { return name }

func (d *driver) Init(context.Context) error { return nil }

func (d *driver) RuntimeConfig() output.RuntimeConfig { return d.cfg.Runtime }

// Send gets 202 once the flow run is queued; a failing run shows only in the flow history.
func (d *driver) Send(ctx context.Context, evt *event.Event) error {
	target, err := d.cfg.DeliveryURL()
	if err != nil {
		return shared.WrapDeliveryError(name, shared.OpTarget, err)
	}
	payload, err := d.buildPayload(evt)
	if err != nil {
		return shared.WrapDeliveryError(name, shared.OpMarshal, err)
	}
	return d.sender.SendRaw(ctx, http.MethodPost, target, payload, "application/json")
}

// HealthCheck is a no-op: the trigger only accepts POST, and any POST runs the flow and posts a message.
func (d *driver) HealthCheck(context.Context) error { return nil }

func (d *driver) Close() error {
	d.sender.Close()
	return nil
}
