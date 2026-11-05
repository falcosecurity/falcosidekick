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

package talon

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

const (
	name = "talon"
	// Talon serves events on "/" and a side-effect-free "/healthz":
	// https://github.com/falcosecurity/falco-talon/blob/main/cmd/server.go
	defaultEndpoint = "/"
	healthRoute     = "/healthz"
)

var targetOptions = shared.HTTPTargetOptions{DefaultEndpoint: defaultEndpoint}

type config struct {
	shared.HTTPTargetConfig `mapstructure:",squash"`
	shared.HTTPConfig       `mapstructure:",squash"`
	Runtime                 output.RuntimeConfig `mapstructure:"runtime"`
}

// OutputType describes the Falco Talon output for the catalog.
var OutputType = output.Type{
	New:      createOutput,
	Name:     name,
	Category: "response",
	Schema: output.Schema{
		Fields: append(shared.HTTPTargetSchemaFields(&targetOptions),
			append(shared.HTTPConfigSchemaFields(), shared.RuntimeConfigSchemaFields()...)...),
	},
}

// payload is the Falco event as Falco posts it, with a title-cased priority.
type payload struct {
	Time         time.Time      `json:"time"`
	OutputFields map[string]any `json:"output_fields"`
	UUID         string         `json:"uuid,omitempty"`
	Output       string         `json:"output"`
	Priority     string         `json:"priority"`
	Rule         string         `json:"rule"`
	Source       string         `json:"source"`
	Hostname     string         `json:"hostname,omitempty"`
	Tags         []string       `json:"tags,omitempty"`
}

type driver struct {
	sender *shared.Sender
	cfg    config
}

func (d *driver) RuntimeConfig() output.RuntimeConfig { return d.cfg.Runtime }

func (c *config) validate() utils.ValidationErrors {
	var errs utils.ValidationErrors
	errs.Merge("", c.HTTPConfig.Validate())
	errs.Merge("", c.HTTPTargetConfig.Validate(&targetOptions))
	if len(errs) > 0 {
		return errs
	}
	return nil
}

func createOutput(raw map[string]any, _ output.Deps) (output.Driver, error) {
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
	return &driver{cfg: cfg, sender: sender}, nil
}

func (d *driver) Name() string { return name }

func (d *driver) Init(_ context.Context) error { return nil }

// Send posts the event to Talon.
func (d *driver) Send(ctx context.Context, evt *event.Event) error {
	target, err := d.cfg.DeliveryURL()
	if err != nil {
		return shared.WrapDeliveryError(name, "target", err)
	}
	return d.sender.SendJSON(ctx, http.MethodPost, target, buildPayload(evt))
}

// HealthCheck sends GET /healthz under base_path. A 401, 403 or 404 means
// the address does not reach Talon.
func (d *driver) HealthCheck(ctx context.Context) error {
	target, err := d.cfg.URL(d.cfg.Host, healthRoute, nil)
	if err != nil {
		return shared.WrapDeliveryError(name, "target", err)
	}
	return d.sender.HealthCheck(ctx, target)
}

func (d *driver) Close() error { return nil }

func buildPayload(evt *event.Event) payload {
	return payload{
		Time:         evt.Time,
		OutputFields: evt.OutputFields,
		UUID:         evt.UUID,
		Output:       evt.Output,
		Priority:     evt.Priority.String(),
		Rule:         evt.Rule,
		Source:       evt.Source,
		Hostname:     evt.Hostname,
		Tags:         evt.Tags,
	}
}
