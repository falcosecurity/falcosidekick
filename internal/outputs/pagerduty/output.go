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

package pagerduty

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

const (
	name = "pagerduty"

	regionUS = "us"
	regionEU = "eu"

	// Service region hosts: https://support.pagerduty.com/main/docs/service-regions
	hostUS = "https://events.pagerduty.com"
	hostEU = "https://events.eu.pagerduty.com"

	// Events API v2: https://docs.pagerduty.com/developer/send-alert-event
	enqueueRoute = "/v2/enqueue"
)

var regions = shared.RegionHosts{Default: regionUS, Hosts: map[string]string{regionUS: hostUS, regionEU: hostEU}}

// DefaultHost is a placeholder: validate sets host from region.
var targetOptions = shared.HTTPTargetOptions{DefaultHost: hostUS, DriverRoutes: true}

type config struct {
	RoutingKey              string `mapstructure:"routing_key"`
	Region                  string `mapstructure:"region"`
	shared.HTTPTargetConfig `mapstructure:",squash"`
	shared.HTTPConfig       `mapstructure:",squash"`
	Runtime                 output.RuntimeConfig `mapstructure:"runtime"`
}

// OutputType describes the PagerDuty output for the catalog.
var OutputType = output.Type{
	New:      createOutput,
	Name:     name,
	Category: "alerting",
	Schema: output.Schema{
		Fields: append(append(shared.RegionTargetSchemaFields(&targetOptions), []output.SchemaField{
			{Name: "routing_key", Type: "string", Required: true, Secret: true, Label: "Routing Key (Integration Key)"},
			regions.SchemaField("Service Region"),
		}...), append(shared.HTTPConfigSchemaFields(), shared.RuntimeConfigSchemaFields()...)...),
	},
}

type driver struct {
	sender *shared.Sender
	cfg    config
}

func (d *driver) RuntimeConfig() output.RuntimeConfig { return d.cfg.Runtime }

func (c *config) validate() utils.ValidationErrors {
	var errs utils.ValidationErrors
	errs.Merge("", c.HTTPConfig.Validate())
	errs.Merge("", regions.Resolve(&c.Region, &c.Host))
	errs.Merge("", c.HTTPTargetConfig.Validate(&targetOptions))
	if strings.TrimSpace(c.RoutingKey) == "" {
		errs.Add("routing_key", "is required")
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

func createOutput(raw map[string]any, _ output.Deps) (output.Driver, error) {
	var cfg config
	if err := shared.DecodeDriverConfig(raw, &cfg); err != nil {
		return nil, fmt.Errorf("pagerduty config: %w", err)
	}
	if errs := cfg.validate(); len(errs) > 0 {
		return nil, fmt.Errorf("pagerduty: %s", errs.Error())
	}
	sender, err := shared.NewSender(name, &cfg.HTTPConfig)
	if err != nil {
		return nil, err
	}
	return &driver{sender: sender, cfg: cfg}, nil
}

func (d *driver) Name() string { return name }

func (d *driver) Init(context.Context) error { return nil }

func (d *driver) Send(ctx context.Context, evt *event.Event) error {
	target, err := d.cfg.URL(d.cfg.Host, enqueueRoute, nil)
	if err != nil {
		return shared.WrapDeliveryError(name, "target", err)
	}
	return d.sender.SendJSON(ctx, http.MethodPost, target, buildEvent(evt, d.cfg.RoutingKey))
}

// HealthCheck is a no-op: the Events API cannot check a routing key without opening an alert.
func (d *driver) HealthCheck(context.Context) error { return nil }

func (d *driver) Close() error { return nil }
