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

package discord

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

const (
	name        = "discord"
	defaultIcon = shared.FalcosidekickIconURL
	waitParam   = "wait"
)

var targetOptions = shared.HTTPTargetOptions{DefaultHost: "https://discord.com", SecretEndpointRequired: true}

type config struct {
	Icon                    string `mapstructure:"icon"`
	shared.HTTPTargetConfig `mapstructure:",squash"`
	shared.HTTPConfig       `mapstructure:",squash"`
	Runtime                 output.RuntimeConfig `mapstructure:"runtime"`
}

// OutputType describes the Discord output for the catalog.
var OutputType = output.Type{
	New:      createOutput,
	Name:     name,
	Category: "chat",
	Schema: output.Schema{
		Fields: append(append(shared.HTTPTargetSchemaFields(&targetOptions), output.SchemaField{
			Name: "icon", Type: "string", Default: defaultIcon, Label: "Avatar URL",
		}), append(shared.HTTPConfigSchemaFields(), shared.RuntimeConfigSchemaFields()...)...),
	},
}

type driver struct {
	sender *shared.Sender
	logger *slog.Logger
	cfg    config
}

func (c *config) validate() utils.ValidationErrors {
	var errs utils.ValidationErrors
	errs.Merge("", c.HTTPConfig.Validate())
	errs.Merge("", c.HTTPTargetConfig.Validate(&targetOptions))
	if c.Icon == "" {
		c.Icon = defaultIcon
	} else if !shared.IsAbsoluteHTTPURL(c.Icon) {
		errs.Add("icon", "must be an absolute http or https URL")
	}
	if _, ok := c.QueryParams[waitParam]; ok {
		errs.Add(fmt.Sprintf("query_params[%q]", waitParam), "is set by the output")
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

func createOutput(raw map[string]any, deps output.Deps) (output.Driver, error) {
	var cfg config
	if err := shared.DecodeDriverConfig(raw, &cfg); err != nil {
		return nil, fmt.Errorf("discord config: %w", err)
	}
	if errs := cfg.validate(); len(errs) > 0 {
		return nil, fmt.Errorf("discord: %s", errs.Error())
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

// Send executes the webhook with wait=true: Discord answers only once the
// message is saved, so a lost message is an error, not a 204.
func (d *driver) Send(ctx context.Context, evt *event.Event) error {
	target, err := d.cfg.URL(d.cfg.Host, d.cfg.DeliveryRoute(), url.Values{waitParam: {"true"}})
	if err != nil {
		return shared.WrapDeliveryError(name, "target", err)
	}
	return d.sender.SendJSON(ctx, http.MethodPost, target, d.buildPayload(evt))
}

// HealthCheck reads the webhook with GET, which returns it without posting
// a message: a wrong token or a deleted webhook answers 401 or 404.
func (d *driver) HealthCheck(ctx context.Context) error {
	target, err := d.cfg.DeliveryURL()
	if err != nil {
		return shared.WrapDeliveryError(name, "target", err)
	}
	return d.sender.HealthCheck(ctx, target)
}

func (d *driver) Close() error { return nil }
