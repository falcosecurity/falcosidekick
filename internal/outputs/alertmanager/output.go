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

package alertmanager

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

const (
	name            = "alertmanager"
	defaultEndpoint = "/api/v2/alerts"
	healthRoute     = "/-/healthy"
)

var targetOptions = shared.HTTPTargetOptions{DefaultEndpoint: defaultEndpoint, ExternalHosts: true}

type config struct {
	ExtraLabels             map[string]string         `mapstructure:"extra_labels"`
	ExtraAnnotations        map[string]string         `mapstructure:"extra_annotations"`
	CustomSeverityMap       map[string]string         `mapstructure:"custom_severity_map"`
	severities              map[event.Priority]string // CustomSeverityMap by parsed priority, set by validate
	GeneratorURL            string                    `mapstructure:"generator_url"`
	shared.HTTPTargetConfig `mapstructure:",squash"`
	shared.HTTPConfig       `mapstructure:",squash"`
	Hosts                   []string             `mapstructure:"hosts"`
	Runtime                 output.RuntimeConfig `mapstructure:"runtime"`
	ExpiresAfter            time.Duration        `mapstructure:"expires_after"`
}

// labelName is the Prometheus label name grammar that Alertmanager validates.
var labelName = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// OutputType describes the Alertmanager output for the catalog.
var OutputType = output.Type{
	New:      createOutput,
	Name:     name,
	Category: output.CategoryAlerting,
	Schema: output.Schema{
		Fields: append(append(shared.HTTPTargetSchemaFields(&targetOptions), []output.SchemaField{
			{
				Name: "hosts", Type: "string[]", Required: true, Label: "Hosts (scheme, host and port)",
				Description: "Alertmanager instances, each as scheme, host and optional port such as `http://alertmanager:9093`. " +
					"Every alert goes to all of them and counts as delivered when at least one accepts it.",
			},
			{
				Name: "generator_url", Type: "string", Label: "Generator URL (link back to source in AM UI)",
				Description: "Link sent as the `generatorURL` of every alert; Alertmanager shows it as the alert source.",
			},
			{
				Name: "expires_after", Type: "string", Default: "0", Label: "Alert Expires After (0 leaves it to Alertmanager's resolve_timeout, 5m by default)",
				Description: "Go duration, such as `30m`, after the event time at which the alert ends, sent as `endsAt`. " +
					"`0` sends no end time, so Alertmanager resolves the alert after its `resolve_timeout`.",
			},
			{
				Name: "extra_labels", Type: "map", Label: "Extra Labels",
				Description: "Labels added to every alert, by label name; they replace built-in labels of the same name. " +
					"Names must match `[a-zA-Z_][a-zA-Z0-9_]*`.",
			},
			{
				Name: "extra_annotations", Type: "map", Label: "Extra Annotations",
				Description: "Annotations added to every alert, by name; they replace the built-in `summary` and `description` of the same name.",
			},
			{
				Name: "custom_severity_map", Type: "map", Label: "Custom Severity Map",
				Description: "Value of the `severity` label by Falco priority, in any case, such as `critical: P1`; other keys are refused. " +
					"Priorities not listed get `critical`, `warning` or `info`.",
			},
		}...), append(shared.HTTPConfigSchemaFields(), shared.RuntimeConfigSchemaFields()...)...),
	},
}

type driver struct {
	sender  *shared.Sender
	logger  *slog.Logger
	warning atomic.Pointer[func(string)]
	cfg     config
}

func (d *driver) RuntimeConfig() output.RuntimeConfig { return d.cfg.Runtime }

func (c *config) validate() utils.ValidationErrors {
	var errs utils.ValidationErrors
	errs.Merge("", c.HTTPConfig.Validate())
	errs.Merge("hosts", shared.ValidateOrigins(c.Hosts))
	errs.Merge("", c.HTTPTargetConfig.Validate(&targetOptions))
	// A bare integer decodes as nanoseconds, so anything below a second is a unit mistake.
	if c.ExpiresAfter < 0 || (c.ExpiresAfter > 0 && c.ExpiresAfter < time.Second) {
		errs.Add("expires_after", "must be 0 or a Go duration of at least 1s, such as 30m")
	}
	for _, key := range shared.SortMapKeys(c.ExtraLabels) {
		if !labelName.MatchString(key) {
			errs.Add(fmt.Sprintf("extra_labels[%q]", key), "name must match [a-zA-Z_][a-zA-Z0-9_]*")
		}
	}
	c.severities = make(map[event.Priority]string, len(c.CustomSeverityMap))
	for _, key := range shared.SortMapKeys(c.CustomSeverityMap) {
		p, err := event.ParsePriority(key)
		_, mapped := c.severities[p]
		switch {
		case err != nil:
			errs.Add(fmt.Sprintf("custom_severity_map[%q]", key), "must be a Falco priority, such as critical")
		case mapped:
			errs.Add(fmt.Sprintf("custom_severity_map[%q]", key), "names a priority already mapped")
		default:
			c.severities[p] = c.CustomSeverityMap[key]
		}
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

	return &driver{
		cfg:    cfg,
		sender: sender,
		logger: shared.ResolveLogger(deps.Logger, name),
	}, nil
}

func (d *driver) Name() string { return name }

func (d *driver) Init(_ context.Context) error { return nil }

func (d *driver) Send(ctx context.Context, evt *event.Event) error {
	alerts := []alertPayload{d.buildAlert(evt)}

	body, err := json.Marshal(alerts)
	if err != nil {
		return shared.WrapDeliveryError(name, shared.OpMarshal, err)
	}

	targets := make([]string, 0, len(d.cfg.Hosts))
	for _, host := range d.cfg.Hosts {
		target, err := d.cfg.URL(host, d.cfg.DeliveryRoute(), nil)
		if err != nil {
			return shared.WrapDeliveryError(name, shared.OpTarget, err)
		}
		targets = append(targets, target)
	}

	if len(targets) == 1 {
		return d.sender.SendRaw(ctx, http.MethodPost, targets[0], body, "application/json")
	}

	return d.fanOut(ctx, targets, body)
}

// fanOut succeeds if at least one host accepts the alert; it fails for good only when every host rejects it.
func (d *driver) fanOut(ctx context.Context, targets []string, body []byte) error {
	errs := make([]error, len(targets))
	var wg sync.WaitGroup
	for hostIndex, url := range targets {
		wg.Go(func() {
			errs[hostIndex] = d.sender.SendRaw(ctx, http.MethodPost, url, body, "application/json")
			if errs[hostIndex] != nil {
				d.logger.Warn("host failed", "host_index", hostIndex, "error", errs[hostIndex])
			}
		})
	}
	wg.Wait()

	failed, permanent := 0, 0
	var last *shared.DeliveryError
	for _, err := range errs {
		if err != nil {
			failed++
			last = shared.NewDeliveryError(name, shared.OpSend, err)
			if output.IsPermanent(err) {
				permanent++
			}
		}
	}
	switch {
	case failed == len(targets):
		return &shared.DeliveryError{
			Cause: ctx.Err(), Output: name, Operation: shared.OpSend,
			Code: fmt.Sprintf("all %d hosts failed, last: %s", failed, last.Reason()), Permanent: permanent == failed,
		}
	case failed > 0:
		d.logger.Warn("partial fan-out", "succeeded", len(targets)-failed, "failed", failed, "total", len(targets))
		d.reportWarning(fmt.Sprintf("%d of %d hosts failed, last: %s", failed, len(targets), last.Reason()))
	default:
		d.reportWarning("")
	}
	return nil
}

func (d *driver) SetWarningHandler(handler func(warning string)) {
	d.warning.Store(&handler)
}

func (d *driver) reportWarning(warning string) {
	if handler := d.warning.Load(); handler != nil {
		(*handler)(warning)
	}
}

// HealthCheck probes hosts concurrently so a slow host does not use up the others' budget.
func (d *driver) HealthCheck(ctx context.Context) error {
	if len(d.cfg.Hosts) == 0 {
		return fmt.Errorf("%s: no hosts configured", name)
	}
	targets := make([]string, len(d.cfg.Hosts))
	for i, host := range d.cfg.Hosts {
		target, err := d.cfg.URL(host, healthRoute, nil)
		if err != nil {
			return shared.WrapDeliveryError(name, shared.OpTarget, err)
		}
		targets[i] = target
	}
	errs := make([]error, len(targets))
	var wg sync.WaitGroup
	for i, target := range targets {
		wg.Go(func() { errs[i] = d.sender.HealthCheck(ctx, target) })
	}
	wg.Wait()

	failed := 0
	for _, err := range errs {
		if errors.Is(err, output.ErrMisconfigured) {
			return err
		}
		if err != nil {
			failed++
		}
	}
	if failed > 0 {
		return &shared.DeliveryError{
			Cause: ctx.Err(), Output: name, Operation: shared.OpHealthcheck,
			Code: fmt.Sprintf("%d of %d hosts unreachable", failed, len(targets)),
		}
	}
	return nil
}

func (d *driver) Close() error {
	d.sender.Close()
	return nil
}
