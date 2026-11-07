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

package shared_test

import (
	"context"
	"maps"
	"net"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
)

func awsConfig(endpoint string, extra map[string]any) map[string]any {
	cfg := map[string]any{"region": "us-east-1", "access_key_id": "a", "secret_access_key": "s", "endpoint": endpoint}
	maps.Copy(cfg, extra)
	return cfg
}

func hostPort(addr string) map[string]any {
	host, port, _ := net.SplitHostPort(addr)
	return map[string]any{"host": host, "port": port}
}

// silentCase builds one registered output against a destination that accepts and never answers.
type silentCase struct {
	config     func(host string) map[string]any
	name       string
	typ        string // output type when it differs from name
	tcp        bool
	noProbe    bool
	kubeconfig bool // host is a kubeconfig for the silent API server
}

// newDriver starts the silent destination and returns the initialized driver, closed at cleanup.
func (c silentCase) newDriver(t *testing.T) output.Driver {
	t.Helper()
	driver := c.build(t)
	require.NoError(t, driver.Init(context.Background()))
	return driver
}

// build starts the silent destination and returns the driver before Init, closed at cleanup.
func (c silentCase) build(t *testing.T) output.Driver {
	t.Helper()
	var host string
	switch {
	case c.tcp:
		host = testutil.HangingTCPServer(t)
	case c.kubeconfig:
		host = testutil.WriteKubeconfig(t, testutil.HangingHTTPServer(t).URL, "", "token")
	default:
		host = testutil.HangingHTTPServer(t).URL
	}
	typ := c.name
	if c.typ != "" {
		typ = c.typ
	}
	driver, err := outputTypes[typ].New(c.config(host), output.Deps{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = driver.Close() })
	return driver
}

// silentCases has one case per registered output with a destination; the check fails when one is missing.
func silentCases(t *testing.T) []silentCase {
	t.Helper()
	cases := []silentCase{
		{name: "webhook", noProbe: true, config: func(h string) map[string]any { return map[string]any{"host": h} }},
		{name: "slack", noProbe: true, config: func(h string) map[string]any { return map[string]any{"host": h, "secret_endpoint": "/services/T/B/X"} }},
		{name: "loki", config: func(h string) map[string]any { return map[string]any{"host": h} }},
		{name: "elasticsearch", config: func(h string) map[string]any { return map[string]any{"host": h} }},
		{name: "alertmanager", config: func(h string) map[string]any { return map[string]any{"hosts": []string{h, h}} }},
		{name: "kafka", tcp: true, config: func(h string) map[string]any {
			return map[string]any{"brokers": []string{h}, "topic": "falco"}
		}},
		{name: "teams", noProbe: true, config: func(h string) map[string]any { return map[string]any{"host": h, "secret_endpoint": "/workflows/x"} }},
		{name: "discord", config: func(h string) map[string]any {
			return map[string]any{"host": h, "secret_endpoint": "/api/webhooks/1/t"}
		}},
		{name: "grafanaoncall", noProbe: true, config: func(h string) map[string]any {
			return map[string]any{"host": h, "secret_endpoint": "/integrations/v1/formatted_webhook/t/"}
		}},
		{name: "talon", config: func(h string) map[string]any { return map[string]any{"host": h} }},
		{name: "cloudevents", noProbe: true, config: func(h string) map[string]any { return map[string]any{"host": h} }},
		{name: "pagerduty", noProbe: true, config: func(h string) map[string]any { return map[string]any{"host": h, "routing_key": "rk"} }},
		{name: "opsgenie", config: func(h string) map[string]any { return map[string]any{"host": h, "api_key": "k"} }},
		{name: "datadog", config: func(h string) map[string]any { return map[string]any{"host": h, "api_key": "k"} }},
		{name: "datadog v2", typ: "datadog", config: func(h string) map[string]any { return map[string]any{"host": h, "api_key": "k", "app_key": "a"} }},
		{name: "awss3", config: func(h string) map[string]any {
			return awsConfig(h, map[string]any{"bucket": "falco", "use_path_style": true})
		}},
		{name: "awssqs", config: func(h string) map[string]any {
			return awsConfig(h, map[string]any{"queue_url": "https://sqs.us-east-1.amazonaws.com/1/q"})
		}},
		{name: "awssns", config: func(h string) map[string]any {
			return awsConfig(h, map[string]any{"topic_arn": "arn:aws:sns:us-east-1:1:t"})
		}},
		{name: "gcppubsub", tcp: true, config: func(h string) map[string]any {
			return map[string]any{"project_id": "p", "topic": "falco", "emulator_host": h}
		}},
		{name: "syslog", tcp: true, config: func(h string) map[string]any {
			cfg := hostPort(h)
			cfg["protocol"] = "tls"
			return cfg
		}},
		{name: "smtp", tcp: true, config: func(h string) map[string]any {
			cfg := hostPort(h)
			cfg["from"], cfg["to"], cfg["auth_mechanism"] = "f@example.com", []string{"t@example.com"}, "none"
			return cfg
		}},
		{name: "redis", tcp: true, config: func(h string) map[string]any { return map[string]any{"address": h} }},
		{name: "otlp", noProbe: true, config: func(h string) map[string]any {
			signal := map[string]any{"endpoint": h}
			return map[string]any{"traces": signal, "logs": signal, "metrics": signal}
		}},
		{name: "policyreport", kubeconfig: true, config: func(h string) map[string]any {
			return map[string]any{"kubeconfig": h, "falco_namespace": "falco"}
		}},
	}
	covered := map[string]bool{"inmemory": true} // stores in process, no destination
	for _, c := range cases {
		covered[c.name] = true
	}
	for name := range outputTypes {
		require.True(t, covered[name], "output %s has no silent-destination case", name)
	}
	return cases
}

// Drivers must stop waiting on a silent destination once ctx ends, or retire and shutdown deadlines cannot hold.
func TestDriversReturnWhenContextEndsOnSilentDestination(t *testing.T) {
	for _, tt := range silentCases(t) {
		t.Run(tt.name, func(t *testing.T) {
			driver := tt.newDriver(t)
			_ = testutil.RequireReturnsOnCancel(t, "Send", func(ctx context.Context) error {
				return driver.Send(ctx, testutil.CreateValidEvent())
			})
			if batch, ok := driver.(output.BatchSender); ok {
				_ = testutil.RequireReturnsOnCancel(t, "SendBatch", func(ctx context.Context) error {
					return batch.SendBatch(ctx, []*event.Event{testutil.CreateValidEvent(), testutil.CreateValidEvent()})
				})
			}
			if !tt.noProbe {
				_ = testutil.RequireReturnsOnCancel(t, "HealthCheck", driver.HealthCheck)
			}
		})
	}
}
