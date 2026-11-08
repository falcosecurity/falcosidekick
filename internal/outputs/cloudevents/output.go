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

package cloudevents

import (
	"context"
	"fmt"
	"maps"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

const (
	name          = "cloudevents"
	defaultSource = "https://falco.org"
)

var targetOptions = shared.HTTPTargetOptions{DefaultEndpoint: "/"}

// Attribute names: https://github.com/cloudevents/spec/blob/v1.0.2/cloudevents/spec.md#attribute-naming-convention
var (
	attributeName = regexp.MustCompile(`^[a-z0-9]+$`)
	// Extensions may not replace the context attributes of the spec or the data member.
	reservedAttributes = []string{"specversion", "id", "source", "type", "time", "datacontenttype", "dataschema", "subject", "data"}
)

type config struct {
	Extensions              map[string]string `mapstructure:"extensions"`
	Source                  string            `mapstructure:"source"`
	shared.HTTPTargetConfig `mapstructure:",squash"`
	shared.HTTPConfig       `mapstructure:",squash"`
	Runtime                 output.RuntimeConfig `mapstructure:"runtime"`
}

// OutputType describes the CloudEvents output for the catalog.
var OutputType = output.Type{
	New:      createOutput,
	Name:     name,
	Category: output.CategoryWebhook,
	Schema: output.Schema{
		Fields: append(append(shared.HTTPTargetSchemaFields(&targetOptions), []output.SchemaField{
			{
				Name: "source", Type: "string", Default: defaultSource, Label: "Event Source (URI reference)",
				Description: "Value of the `source` attribute of every event, a URI reference such as `https://falco.org` or `/cluster/prod`. Empty uses the default.",
			},
			{
				Name: "extensions", Type: "map", Label: "Extension Attributes",
				Description: "Extension attributes sent as `ce-` headers with every event, by name of lowercase letters and digits. " +
					"They replace the built-in `priority`, `rule`, `eventsource` and `hostname`; spec attributes such as `id` are refused.",
			},
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
	errs.Merge("", c.HTTPTargetConfig.Validate(&targetOptions))
	if c.Source == "" {
		c.Source = defaultSource
	} else if !validString(c.Source) {
		errs.Add("source", "must not contain control characters")
	} else if _, err := url.Parse(c.Source); err != nil {
		errs.Add("source", "must be a URI reference")
	}
	for _, key := range slices.Sorted(maps.Keys(c.Extensions)) {
		field := fmt.Sprintf("extensions[%q]", key)
		switch {
		case !attributeName.MatchString(key):
			errs.Add(field, "name must contain only lowercase letters a-z and digits 0-9")
		case slices.Contains(reservedAttributes, key):
			errs.Add(field, "name is a CloudEvents context attribute")
		case !validString(c.Extensions[key]):
			errs.Add(field, "value must not contain control characters")
		}
	}
	for header := range c.Headers {
		if lower := strings.ToLower(header); strings.HasPrefix(lower, "ce-") || lower == "content-type" {
			errs.Add(fmt.Sprintf("headers[%q]", header), "is set by the output; use source or extensions")
		}
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

// validString applies the CloudEvents String type: valid UTF-8 without U+0000-U+001F and U+007F-U+009F.
func validString(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r <= 0x1F || (r >= 0x7F && r <= 0x9F) {
			return false
		}
	}
	return true
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
	return &driver{sender: sender, cfg: cfg}, nil
}

func (d *driver) Name() string { return name }

func (d *driver) Init(context.Context) error { return nil }

func (d *driver) Send(ctx context.Context, evt *event.Event) error {
	target, err := d.cfg.DeliveryURL()
	if err != nil {
		return shared.WrapDeliveryError(name, shared.OpTarget, err)
	}
	req, err := newRequest(ctx, target, evt, d.cfg.Source, d.cfg.Extensions)
	if err != nil {
		return err
	}
	return d.sender.Do(ctx, req)
}

// HealthCheck is a no-op: receivers have no standard probe and may take any request as an event.
func (d *driver) HealthCheck(context.Context) error { return nil }

func (d *driver) Close() error {
	d.sender.Close()
	return nil
}
