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

package shared

import (
	"errors"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strings"

	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

const msgEndpointConflict = "cannot be combined with secret_endpoint"

// HTTPTargetConfig is where an HTTP output delivers; credentials belong in secret_endpoint or query_params.
type HTTPTargetConfig struct {
	QueryParams    map[string]ValueSources `mapstructure:"query_params"`
	Host           string                  `mapstructure:"host"`
	BasePath       string                  `mapstructure:"base_path"`
	Endpoint       string                  `mapstructure:"endpoint"`
	SecretEndpoint string                  `mapstructure:"secret_endpoint"`
}

// HTTPTargetOptions holds the rules that differ between outputs.
type HTTPTargetOptions struct {
	// DefaultHost is used when host is empty. Without it, host is required.
	DefaultHost string
	// DefaultEndpoint is used when neither endpoint nor secret_endpoint is set.
	DefaultEndpoint string
	// ReservedQueryParams lists names the driver sets itself.
	ReservedQueryParams []string
	// ExternalHosts means the driver owns its hosts, so host is rejected.
	ExternalHosts bool
	// DriverRoutes means the driver owns every route, so endpoint and secret_endpoint are rejected.
	DriverRoutes bool
	// SecretEndpointRequired means the delivery path is always a credential.
	SecretEndpointRequired bool
}

// Validate applies defaults and checks the address; it reads query files so an unreadable one fails at load.
func (c *HTTPTargetConfig) Validate(opts *HTTPTargetOptions) utils.ValidationErrors {
	var errs utils.ValidationErrors
	errs.Merge("", c.validateHost(opts))
	errs.Merge("base_path", ValidateEndpoint(c.BasePath))
	c.BasePath = strings.TrimRight(c.BasePath, "/")
	errs.Merge("", c.validateRoute(opts))
	errs.Merge("", c.validateQuery(opts))
	return errs
}

func (c *HTTPTargetConfig) validateHost(opts *HTTPTargetOptions) utils.ValidationErrors {
	var errs utils.ValidationErrors
	if opts.ExternalHosts {
		if c.Host != "" {
			errs.Add(fieldHost, "is not supported; use hosts")
		}
		return errs
	}
	if c.Host == "" {
		c.Host = opts.DefaultHost
	}
	errs.Merge(fieldHost, ValidateOrigin(c.Host))
	return errs
}

func (c *HTTPTargetConfig) validateRoute(opts *HTTPTargetOptions) utils.ValidationErrors {
	var errs utils.ValidationErrors
	switch {
	case opts.DriverRoutes:
		if c.Endpoint != "" {
			errs.Add("endpoint", "is not supported; routes are set by the output")
		}
		if c.SecretEndpoint != "" {
			errs.Add("secret_endpoint", "is not supported; routes are set by the output")
		}
		return errs
	case opts.SecretEndpointRequired:
		if c.Endpoint != "" {
			errs.Add("endpoint", "is not supported; use secret_endpoint")
		}
		if c.SecretEndpoint == "" {
			errs.Add("secret_endpoint", "is required")
		}
	case c.Endpoint != "" && c.SecretEndpoint != "":
		errs.Add("endpoint", msgEndpointConflict)
	}
	errs.Merge("endpoint", ValidateEndpoint(c.Endpoint))
	errs.Merge("secret_endpoint", ValidateEndpoint(c.SecretEndpoint))
	if c.Endpoint == "" && c.SecretEndpoint == "" {
		c.Endpoint = opts.DefaultEndpoint
	}
	return errs
}

func (c *HTTPTargetConfig) validateQuery(opts *HTTPTargetOptions) utils.ValidationErrors {
	var errs utils.ValidationErrors
	for _, name := range slices.Sorted(maps.Keys(c.QueryParams)) {
		field := fmt.Sprintf("query_params[%q]", name)
		if name == "" {
			errs.Add("query_params", "parameter name must not be empty")
			continue
		}
		if slices.Contains(opts.ReservedQueryParams, name) {
			errs.Add(field, "is set by the output")
			continue
		}
		if _, err := c.QueryParams[name].resolveQuery(); err != nil {
			errs.Add(field, err.Error())
		}
	}
	return errs
}

func (h ValueSources) resolveQuery() ([]string, error) {
	return h.resolveSources("query", nil)
}

// DeliveryRoute returns the configured delivery path, public or secret.
func (c *HTTPTargetConfig) DeliveryRoute() string {
	if c.SecretEndpoint != "" {
		return c.SecretEndpoint
	}
	return c.Endpoint
}

// DeliveryURL returns the delivery URL on host. See URL.
func (c *HTTPTargetConfig) DeliveryURL() (string, error) {
	return c.URL(c.Host, c.DeliveryRoute(), nil)
}

// URL joins host, base_path, a validated route and the queries, rereading query files.
// Errors name no configured value; drivers wrap them with the "target" operation.
func (c *HTTPTargetConfig) URL(host, route string, query url.Values) (string, error) {
	target, err := url.Parse(host + c.BasePath + route)
	if err != nil {
		return "", errors.New("invalid endpoint address")
	}
	merged := make(url.Values, len(query)+len(c.QueryParams))
	maps.Copy(merged, query)
	for _, name := range slices.Sorted(maps.Keys(c.QueryParams)) {
		values, err := c.QueryParams[name].resolveQuery()
		if err != nil {
			return "", fmt.Errorf("query_params[%q]: %w", name, err)
		}
		if len(values) > 0 {
			merged[name] = values
		}
	}
	target.RawQuery = merged.Encode()
	return target.String(), nil
}

// HTTPTargetSchemaFields returns the address fields an output exposes.
func HTTPTargetSchemaFields(opts *HTTPTargetOptions) []output.SchemaField {
	var fields []output.SchemaField
	if !opts.ExternalHosts {
		host := output.SchemaField{Name: fieldHost, Type: "string", Required: opts.DefaultHost == "", Label: "Host (scheme, host and port)"}
		if opts.DefaultHost != "" {
			host.Default = opts.DefaultHost
		}
		fields = append(fields, host)
	}
	fields = append(fields, output.SchemaField{Name: "base_path", Type: "string", Label: "Base Path"})
	if !opts.DriverRoutes && !opts.SecretEndpointRequired {
		endpoint := output.SchemaField{Name: "endpoint", Type: "string", Label: "Endpoint"}
		if opts.DefaultEndpoint != "" {
			endpoint.Default = opts.DefaultEndpoint
		}
		fields = append(fields, endpoint)
	}
	if !opts.DriverRoutes {
		fields = append(fields, output.SchemaField{
			Name: "secret_endpoint", Type: "string", Secret: true,
			Required: opts.SecretEndpointRequired, Label: "Secret Endpoint",
		})
	}
	return append(fields, output.SchemaField{Name: "query_params", Type: "map", Label: "Query Parameters", EntryFields: []output.SchemaField{
		{Name: "values", Type: "string[]", Label: "Public Values"},
		{Name: "secrets", Type: "string[]", Secret: true, Label: "Secret Values"},
		{Name: "files", Type: "string[]", File: true, Label: "Secret File Paths"},
	}})
}
