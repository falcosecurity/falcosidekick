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

package slack

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"text/template"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

const (
	defaultFooter = "https://github.com/falcosecurity/falcosidekick"
	formatAll     = "all"
	formatFields  = "fields"
	formatText    = "text"
)

var targetOptions = shared.HTTPTargetOptions{DefaultHost: "https://hooks.slack.com", SecretEndpointRequired: true}

type config struct {
	Channel                 string `mapstructure:"channel"`
	Footer                  string `mapstructure:"footer"`
	IconURL                 string `mapstructure:"icon_url"`
	IconEmoji               string `mapstructure:"icon_emoji"`
	BotUsername             string `mapstructure:"bot_username"`
	OutputFormat            string `mapstructure:"output_format"`
	MessageFormat           string `mapstructure:"message_format"`
	shared.HTTPTargetConfig `mapstructure:",squash"`
	shared.HTTPConfig       `mapstructure:",squash"`
	Runtime                 output.RuntimeConfig `mapstructure:"runtime"`
}

// OutputType describes the Slack output for the catalog.
var OutputType = output.Type{
	New:      createOutput,
	Name:     "slack",
	Category: "chat",
	Schema: output.Schema{
		Fields: append(append(shared.HTTPTargetSchemaFields(&targetOptions), []output.SchemaField{
			{Name: "channel", Type: "string", Label: "Channel"},
			{Name: "bot_username", Type: "string", Label: "Bot Username"},
			{Name: "icon_url", Type: "string", Label: "Icon URL"},
			{Name: "icon_emoji", Type: "string", Label: "Icon Emoji (e.g., :ghost:)"},
			{Name: "output_format", Type: "enum", Values: []string{"all", "fields", "text"}, Default: "all", Label: "Output Format"},
			{Name: "message_format", Type: "string", Label: "Message Template"},
			{Name: "footer", Type: "string", Label: "Footer"},
		}...), append(shared.HTTPConfigSchemaFields(), shared.RuntimeConfigSchemaFields()...)...),
	},
}

type driver struct {
	sender      *shared.Sender
	logger      *slog.Logger
	messageTmpl *template.Template
	cfg         config
}

func (d *driver) RuntimeConfig() output.RuntimeConfig { return d.cfg.Runtime }

var validOutputFormats = map[string]bool{formatAll: true, formatFields: true, formatText: true}

func (c *config) validate() utils.ValidationErrors {
	var errs utils.ValidationErrors
	errs.Merge("", c.HTTPConfig.Validate())
	errs.Merge("", c.HTTPTargetConfig.Validate(&targetOptions))
	if c.OutputFormat == "" {
		c.OutputFormat = formatAll
	} else if !validOutputFormats[c.OutputFormat] {
		errs.Add("output_format", fmt.Sprintf("must be all/fields/text, got %q", c.OutputFormat))
	}
	if c.MessageFormat != "" {
		if _, err := template.New("").Parse(c.MessageFormat); err != nil {
			errs.Add("message_format", fmt.Sprintf("invalid Go template: %v", err))
		}
	}
	if c.Footer == "" {
		c.Footer = defaultFooter
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

func createOutput(raw map[string]any, deps output.Deps) (output.Driver, error) {
	var cfg config
	if err := shared.DecodeDriverConfig(raw, &cfg); err != nil {
		return nil, fmt.Errorf("slack config: %w", err)
	}
	if errs := cfg.validate(); len(errs) > 0 {
		return nil, fmt.Errorf("slack: %s", errs.Error())
	}

	sender, err := shared.NewSender("slack", &cfg.HTTPConfig)
	if err != nil {
		return nil, err
	}

	o := &driver{
		cfg:    cfg,
		sender: sender,
		logger: shared.ResolveLogger(deps.Logger, "slack"),
	}

	if cfg.MessageFormat != "" {
		tmpl, err := template.New("slack").Parse(cfg.MessageFormat)
		if err != nil {
			return nil, fmt.Errorf("slack: parse message template: %w", err)
		}
		o.messageTmpl = tmpl
	}

	return o, nil
}

func (d *driver) Name() string { return "slack" }

func (d *driver) Init(_ context.Context) error { return nil }

// Send delivers an event as a Slack attachment.
// Checks the response body because Slack returns HTTP 200 with error text on failure.
func (d *driver) Send(ctx context.Context, evt *event.Event) error {
	target, err := d.cfg.DeliveryURL()
	if err != nil {
		return shared.WrapDeliveryError("slack", "target", err)
	}
	return d.sender.SendJSONCheckBody(ctx, http.MethodPost, target, d.buildPayload(evt), checkSlackResponse)
}

// HealthCheck is a no-op: the endpoint only accepts POST, so no request can
// probe it without delivering a message.
func (d *driver) HealthCheck(context.Context) error { return nil }

func (d *driver) Close() error { return nil }

// checkSlackResponse validates the Slack webhook response body.
// Slack returns HTTP 200 with body "ok" on success, or error text like
// "invalid_payload", "channel_not_found", "no_service" on failure.
func checkSlackResponse(body []byte) error {
	body = bytes.TrimSpace(body)
	if len(body) == 0 || bytes.Equal(body, []byte("ok")) {
		return nil
	}
	code := string(body)
	switch code {
	case "action_prohibited", "channel_is_archived", "channel_not_found", "invalid_payload", "invalid_token",
		"no_active_hooks", "no_service", "no_service_id", "no_team", "no_text", "posting_to_general_channel_denied",
		"rollup_error", "team_disabled", "too_many_attachments", "user_not_found":
		return shared.NewProtocolError("slack", code)
	default:
		return shared.NewProtocolError("slack", "unexpected response")
	}
}
