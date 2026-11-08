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

package datadog

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

const (
	name        = "datadog"
	defaultSite = "datadoghq.com"
	apiKeyName  = "DD-API-KEY"         //nolint:gosec // header name, not a credential
	appKeyName  = "DD-APPLICATION-KEY" //nolint:gosec // header name, not a credential

	// Events API v2 needs both keys: https://docs.datadoghq.com/api/latest/events/#post-an-event
	eventsRoute = "/api/v2/events"
	// https://docs.datadoghq.com/api/latest/key-management/#validate-api-and-application-keys
	validateKeysRoute = "/api/v2/validate_keys"
)

// Key validation uses api.<site>; events use event-management-intake.<site>.
var sites = []string{
	"datadoghq.com", "us3.datadoghq.com", "us5.datadoghq.com", "datadoghq.eu",
	"ap1.datadoghq.com", "ap2.datadoghq.com", "uk1.datadoghq.com", "ddog-gov.com", "us2.ddog-gov.com",
}

// DefaultHost is a placeholder replaced from site; api_key is reserved so the key never reaches a URL.
var targetOptions = shared.HTTPTargetOptions{
	DefaultHost:         apiHost(defaultSite),
	DriverRoutes:        true,
	ReservedQueryParams: []string{"api_key"},
}

type config struct {
	APIKey string `mapstructure:"api_key"`
	AppKey string `mapstructure:"app_key"`
	Site   string `mapstructure:"site"`
	// intakeHost receives events; it equals Host when host is set.
	intakeHost              string
	shared.HTTPTargetConfig `mapstructure:",squash"`
	shared.HTTPConfig       `mapstructure:",squash"`
	Runtime                 output.RuntimeConfig `mapstructure:"runtime"`
}

// OutputType describes the Datadog output for the catalog.
var OutputType = output.Type{
	New:      createOutput,
	Name:     name,
	Category: output.CategoryAlerting,
	Schema: output.Schema{
		Fields: append(append(targetSchemaFields(), []output.SchemaField{
			{
				Name: "api_key", Type: "string", Required: true, Secret: true, Label: "API Key",
				Description: "Datadog API key, sent in the `DD-API-KEY` header.",
			},
			{
				Name: "app_key", Type: "string", Required: true, Secret: true, Label: "Application Key",
				Description: "Datadog application key, sent in the `DD-APPLICATION-KEY` header; Events API v2 requires it with the API key.",
			},
			{
				Name: "site", Type: "enum", Values: sites, Default: defaultSite, Label: "Datadog Site",
				Description: "Datadog site of the organization, which selects the API hosts.",
			},
		}...), append(shared.HTTPConfigSchemaFields(), shared.RuntimeConfigSchemaFields()...)...),
	},
}

// targetSchemaFields leaves host without a default because site selects it.
func targetSchemaFields() []output.SchemaField {
	fields := shared.HTTPTargetSchemaFields(&targetOptions)
	for i := range fields {
		if fields[i].Name == "host" {
			fields[i].Default = nil
			fields[i].Label = "Host (scheme, host and port; replaces every Datadog host; default from site)"
			fields[i].Description = "Address that replaces every Datadog host, as scheme, host and optional port, such as a proxy. Empty uses the hosts of the site."
		}
	}
	return fields
}

func apiHost(site string) string { return "https://api." + site }

func intakeHost(site string) string { return "https://event-management-intake." + site }

type driver struct {
	sender *shared.Sender
	cfg    config
}

func (d *driver) RuntimeConfig() output.RuntimeConfig { return d.cfg.Runtime }

func (c *config) validate() utils.ValidationErrors {
	var errs utils.ValidationErrors
	errs.Merge("", c.HTTPConfig.Validate())
	c.Site = strings.ToLower(c.Site)
	if c.Site == "" {
		c.Site = defaultSite
	}
	switch {
	case !slices.Contains(sites, c.Site):
		errs.Add("site", "must be one of "+strings.Join(sites, "/"))
	case c.Host == "":
		c.Host, c.intakeHost = apiHost(c.Site), intakeHost(c.Site)
	default:
		c.intakeHost = c.Host
	}
	errs.Merge("", c.HTTPTargetConfig.Validate(&targetOptions))
	errs.Merge("", c.ValidateCredential(shared.CredentialHeader{Field: "api_key", Header: apiKeyName, Required: true}, c.APIKey))
	errs.Merge("", c.ValidateCredential(shared.CredentialHeader{Field: "app_key", Header: appKeyName, Required: true}, c.AppKey))
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
	sender.SetHeader(apiKeyName, cfg.APIKey)
	sender.SetHeader(appKeyName, cfg.AppKey)
	return &driver{sender: sender, cfg: cfg}, nil
}

func (d *driver) Name() string { return name }

func (d *driver) Init(context.Context) error { return nil }

func (d *driver) Send(ctx context.Context, evt *event.Event) error {
	target, err := d.cfg.URL(d.cfg.intakeHost, eventsRoute, nil)
	if err != nil {
		return shared.WrapDeliveryError(name, shared.OpTarget, err)
	}
	return d.sender.SendJSON(ctx, http.MethodPost, target, newPayload(evt))
}

// HealthCheck validates both keys without posting an event.
func (d *driver) HealthCheck(ctx context.Context) error {
	target, err := d.cfg.URL(d.cfg.Host, validateKeysRoute, nil)
	if err != nil {
		return shared.WrapDeliveryError(name, shared.OpTarget, err)
	}
	return d.sender.HealthCheck(ctx, target)
}

func (d *driver) Close() error {
	d.sender.Close()
	return nil
}
