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

package opsgenie

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
	name = "opsgenie"

	regionUS = "us"
	regionEU = "eu"

	// https://docs.opsgenie.com/docs/alert-api
	hostUS      = "https://api.opsgenie.com"
	hostEU      = "https://api.eu.opsgenie.com"
	alertsRoute = "/v2/alerts"
	// https://docs.opsgenie.com/docs/heartbeat-api#list-heartbeats
	heartbeatsRoute = "/v2/heartbeats"
)

var regions = shared.RegionHosts{Default: regionUS, Hosts: map[string]string{regionUS: hostUS, regionEU: hostEU}}

// Opsgenie API keys travel as "Authorization: GenieKey <key>".
var apiKeyHeader = shared.CredentialHeader{Field: "api_key", Header: "Authorization", Required: true}

// DefaultHost is a placeholder: validate sets host from region.
var targetOptions = shared.HTTPTargetOptions{DefaultHost: hostUS, DriverRoutes: true}

type config struct {
	APIKey                  string `mapstructure:"api_key"`
	Region                  string `mapstructure:"region"`
	shared.HTTPTargetConfig `mapstructure:",squash"`
	shared.HTTPConfig       `mapstructure:",squash"`
	Runtime                 output.RuntimeConfig `mapstructure:"runtime"`
}

// OutputType describes the Opsgenie output for the catalog.
var OutputType = output.Type{
	New:      createOutput,
	Name:     name,
	Category: "alerting",
	Schema: output.Schema{
		Fields: append(append(shared.RegionTargetSchemaFields(&targetOptions), []output.SchemaField{
			{Name: "api_key", Type: "string", Required: true, Secret: true, Label: "API Key (API integration)"},
			regions.SchemaField("Region"),
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
	errs.Merge("", c.ValidateCredential(apiKeyHeader, c.APIKey))
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
	sender.SetHeader("Authorization", "GenieKey "+cfg.APIKey)
	return &driver{sender: sender, cfg: cfg}, nil
}

func (d *driver) Name() string { return name }

func (d *driver) Init(context.Context) error { return nil }

// Send gets 202: Opsgenie creates the alert asynchronously.
func (d *driver) Send(ctx context.Context, evt *event.Event) error {
	target, err := d.cfg.URL(d.cfg.Host, alertsRoute, nil)
	if err != nil {
		return shared.WrapDeliveryError(name, shared.OpTarget, err)
	}
	return d.sender.SendJSON(ctx, http.MethodPost, target, buildAlert(evt))
}

// HealthCheck lists heartbeats; 403 is transient because an alert-only key is refused there.
// https://docs.opsgenie.com/docs/response
func (d *driver) HealthCheck(ctx context.Context) error {
	target, err := d.cfg.URL(d.cfg.Host, heartbeatsRoute, nil)
	if err != nil {
		return shared.WrapDeliveryError(name, shared.OpTarget, err)
	}
	return d.sender.HealthCheck(ctx, target, http.StatusForbidden)
}

func (d *driver) Close() error { return nil }
