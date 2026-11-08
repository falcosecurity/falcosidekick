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

package grafanaoncall

import (
	"context"
	"fmt"
	"net/http"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

const (
	name          = "grafanaoncall"
	stateAlerting = "alerting"
)

// No default host: Grafana Cloud and self-hosted engines differ, and the path carries the token.
var targetOptions = shared.HTTPTargetOptions{SecretEndpointRequired: true}

type config struct {
	shared.HTTPTargetConfig `mapstructure:",squash"`
	shared.HTTPConfig       `mapstructure:",squash"`
	Runtime                 output.RuntimeConfig `mapstructure:"runtime"`
}

// OutputType describes the Grafana OnCall output for the catalog.
var OutputType = output.Type{
	New:      createOutput,
	Name:     name,
	Category: output.CategoryAlerting,
	Schema: output.Schema{
		Fields: append(shared.HTTPTargetSchemaFields(&targetOptions),
			append(shared.HTTPConfigSchemaFields(), shared.RuntimeConfigSchemaFields()...)...),
	},
}

// https://grafana.com/docs/grafana-cloud/alerting-and-irm/irm/configure/integrations/webhooks/incoming-webhooks/oncall-webhooks
type payload struct {
	AlertUID string `json:"alert_uid"`
	State    string `json:"state"`
	Title    string `json:"title"`
	Message  string `json:"message"`
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

func (d *driver) Send(ctx context.Context, evt *event.Event) error {
	target, err := d.cfg.DeliveryURL()
	if err != nil {
		return shared.WrapDeliveryError(name, shared.OpTarget, err)
	}
	return d.sender.SendJSON(ctx, http.MethodPost, target, buildPayload(evt))
}

// HealthCheck is a no-op: the integration only accepts POST, which creates an alert.
func (d *driver) HealthCheck(context.Context) error { return nil }

func (d *driver) Close() error {
	d.sender.Close()
	return nil
}

func buildPayload(evt *event.Event) payload {
	return payload{
		AlertUID: evt.UUID,
		State:    stateAlerting,
		Title:    fmt.Sprintf("[%s] %s", evt.Priority.String(), evt.Rule),
		Message:  evt.Output,
	}
}
