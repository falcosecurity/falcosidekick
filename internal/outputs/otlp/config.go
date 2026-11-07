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

package otlp

import (
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

const (
	protocolGRPC = "grpc"
	protocolHTTP = "http/protobuf"

	schemeHTTP  = "http"
	schemeHTTPS = "https"

	compressionNone = "none"
	compressionGzip = "gzip"

	defaultTimeout = 10 * time.Second
)

type config struct {
	Traces  *tracesConfig        `mapstructure:"traces"`
	Logs    *signalConfig        `mapstructure:"logs"`
	Metrics *metricsConfig       `mapstructure:"metrics"`
	Runtime output.RuntimeConfig `mapstructure:"runtime"`
}

type signalConfig struct {
	Headers     map[string]shared.ValueSources `mapstructure:"headers"`
	Endpoint    string                         `mapstructure:"endpoint"`
	Protocol    string                         `mapstructure:"protocol"`
	Compression string                         `mapstructure:"compression"`
	TLS         shared.TLSClientConfig         `mapstructure:"tls"`
	Timeout     time.Duration                  `mapstructure:"timeout"`
}

type tracesConfig struct {
	signalConfig `mapstructure:",squash"`
	Duration     time.Duration `mapstructure:"duration"`
}

type metricsConfig struct {
	ExtraAttributes []string `mapstructure:"extra_attributes"`
	signalConfig    `mapstructure:",squash"`
}

// target is a validated endpoint split for the exporter options.
type target struct {
	host   string
	path   string
	secure bool
}

func (c *signalConfig) applyDefaults() {
	if c.Protocol == "" {
		c.Protocol = protocolHTTP
	}
	if c.Compression == "" {
		c.Compression = compressionNone
	}
	if c.Timeout == 0 {
		c.Timeout = defaultTimeout
	}
}

func (c *signalConfig) validate() utils.ValidationErrors {
	var errs utils.ValidationErrors
	if c.Protocol != protocolGRPC && c.Protocol != protocolHTTP {
		errs.Add("protocol", "must be grpc or http/protobuf")
	}
	if c.Compression != compressionNone && c.Compression != compressionGzip {
		errs.Add("compression", "must be none or gzip")
	}
	if c.Timeout < 0 {
		errs.Add("timeout", "must be positive")
	}
	if problem := c.endpointProblem(); problem != "" {
		errs.Add("endpoint", problem)
	}
	headers := shared.HTTPConfig{Headers: c.Headers, TLS: c.TLS}
	errs.Merge("", headers.Validate())
	if len(errs) > 0 {
		return errs
	}
	return nil
}

func (c *signalConfig) endpointProblem() string {
	if c.Endpoint == "" {
		return "is required"
	}
	u, err := url.Parse(c.Endpoint)
	switch {
	case err != nil:
		return "invalid URL"
	case u.Scheme != schemeHTTP && u.Scheme != schemeHTTPS, u.Host == "":
		return "must be an http or https URL with a host"
	case u.User != nil:
		return "must not include credentials; use headers"
	case u.RawQuery != "" || u.Fragment != "" || strings.HasSuffix(c.Endpoint, "?"):
		return "must not include a query or fragment"
	case c.Protocol == protocolGRPC && strings.Trim(u.Path, "/") != "":
		return "must not include a path with protocol grpc"
	case u.Scheme == schemeHTTP && c.TLS != (shared.TLSClientConfig{}):
		return "tls settings require an https endpoint"
	}
	return ""
}

// target applies defaultPath to an http/protobuf endpoint without a path.
func (c *signalConfig) target(defaultPath string) target {
	u, _ := url.Parse(c.Endpoint)
	path := u.Path
	if path == "" || path == "/" {
		path = defaultPath
	}
	return target{host: u.Host, path: path, secure: u.Scheme == schemeHTTPS}
}

// url is the full HTTP endpoint; given whole, its scheme overrides the OTEL_*_INSECURE variables.
func (t target) url() string {
	scheme := schemeHTTP
	if t.secure {
		scheme = schemeHTTPS
	}
	return scheme + "://" + t.host + t.path
}

// resolveHeaders reads header values, secrets and files once.
func (c *signalConfig) resolveHeaders() (map[string]string, error) {
	req := &http.Request{Header: http.Header{}}
	if err := shared.ApplyHeaders(req, c.Headers); err != nil {
		return nil, err
	}
	headers := make(map[string]string, len(req.Header))
	for name, values := range req.Header {
		headers[name] = strings.Join(values, ",")
	}
	return headers, nil
}

func (c *metricsConfig) validateAttributes() utils.ValidationErrors {
	var errs utils.ValidationErrors
	seen := make(map[string]bool, len(c.ExtraAttributes))
	for i, field := range c.ExtraAttributes {
		key := fmt.Sprintf("extra_attributes[%d]", i)
		switch {
		case strings.TrimSpace(field) == "":
			errs.Add(key, "must be an output field name")
		case slices.Contains(reservedAttributes, field):
			errs.Add(key, fmt.Sprintf("%q is set on every data point", field))
		case seen[field]:
			errs.Add(key, fmt.Sprintf("duplicate field %q", field))
		}
		seen[field] = true
	}
	return errs
}

func (c *config) applyDefaults() {
	if c.Traces != nil {
		c.Traces.applyDefaults()
	}
	if c.Logs != nil {
		c.Logs.applyDefaults()
	}
	if c.Metrics != nil {
		c.Metrics.applyDefaults()
	}
}

func (c *config) validate() utils.ValidationErrors {
	var errs utils.ValidationErrors
	if c.Traces == nil && c.Logs == nil && c.Metrics == nil {
		errs.Add("", "at least one of traces, logs or metrics is required")
	}
	if c.Traces != nil {
		errs.Merge(signalTraces, c.Traces.validate())
		if c.Traces.Duration < 0 {
			errs.Add(signalTraces+".duration", "must be positive")
		}
	}
	if c.Logs != nil {
		errs.Merge(signalLogs, c.Logs.validate())
	}
	if c.Metrics != nil {
		errs.Merge(signalMetrics, c.Metrics.validate())
		errs.Merge(signalMetrics, c.Metrics.validateAttributes())
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

func schemaFields() []output.SchemaField {
	var fields []output.SchemaField
	for _, signal := range []string{signalTraces, signalLogs, signalMetrics} {
		fields = append(fields,
			output.SchemaField{Name: signal + ".endpoint", Type: "string", Label: "Endpoint URL (enables " + signal + ")"},
			output.SchemaField{Name: signal + ".protocol", Type: "enum", Values: []string{protocolHTTP, protocolGRPC}, Default: protocolHTTP, Label: "Protocol"},
			output.SchemaField{Name: signal + ".compression", Type: "enum", Values: []string{compressionNone, compressionGzip}, Default: compressionNone, Label: "Compression"},
			output.SchemaField{Name: signal + ".timeout", Type: "string", Default: defaultTimeout.String(), Label: "Export Timeout"},
		)
		for _, f := range shared.HTTPConfigSchemaFields() {
			if f.Name == "headers" || strings.HasPrefix(f.Name, "tls.") {
				f.Name = signal + "." + f.Name
				fields = append(fields, f)
			}
		}
		switch signal {
		case signalTraces:
			fields = append(fields, output.SchemaField{Name: signal + ".duration", Type: "string", Default: "0s", Label: "Span Duration"})
		case signalMetrics:
			fields = append(fields, output.SchemaField{Name: signal + ".extra_attributes", Type: "string[]", Label: "Output Fields as Metric Attributes"})
		}
	}
	return append(fields, shared.RuntimeConfigSchemaFields()...)
}
