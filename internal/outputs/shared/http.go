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
	"fmt"
	"net/http"
	"time"

	"golang.org/x/net/http/httpguts"

	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

const (
	defaultTimeout         = 10 * time.Second
	defaultMaxIdleConns    = 10
	defaultIdleConnTimeout = 30 * time.Second
)

// HTTPConfig holds shared HTTP client settings for outputs.
type HTTPConfig struct {
	Headers     map[string]ValueSources `mapstructure:"headers"`
	Username    string                  `mapstructure:"username"`
	Password    string                  `mapstructure:"password"`
	BearerToken string                  `mapstructure:"bearer_token"`
	TLS         TLSClientConfig         `mapstructure:"tls"`
}

// Validate checks HTTP config for inconsistencies.
func (c *HTTPConfig) Validate() utils.ValidationErrors {
	var errs utils.ValidationErrors
	if c.BearerToken != "" && c.Password != "" {
		errs.Add("bearer_token", "cannot use both bearer_token and basic auth (username/password)")
	}
	if !httpguts.ValidHeaderFieldValue(c.BearerToken) {
		errs.Add("bearer_token", "invalid header value")
	}
	errs.Merge("", c.validateHeaders())
	errs.Merge("tls", c.TLS.Validate())
	if len(errs) > 0 {
		return errs
	}
	return nil
}

// HTTPConfigSchemaFields returns schema fields common to all HTTP outputs.
func HTTPConfigSchemaFields() []output.SchemaField {
	return append([]output.SchemaField{
		{Name: "username", Type: "string", Label: "Username (Basic Auth)"},
		{Name: "password", Type: "string", Secret: true, Label: "Password (Basic Auth)"},
		{Name: "bearer_token", Type: "string", Secret: true, Label: "Bearer Token"},
		{Name: "headers", Type: "map", Label: "Custom HTTP Headers", EntryFields: []output.SchemaField{
			{Name: "values", Type: "string[]", Label: "Public Values"},
			{Name: "secrets", Type: "string[]", Secret: true, Label: "Secret Values"},
			{Name: "files", Type: "string[]", Label: "Secret File Paths"},
		}},
	}, TLSClientSchemaFields()...)
}

// BuildHTTPClient creates an HTTP client from shared config including TLS.
func BuildHTTPClient(cfg *HTTPConfig) (*http.Client, error) {
	tlsCfg, err := BuildTLSConfig(&cfg.TLS)
	if err != nil {
		return nil, fmt.Errorf("http client tls: %w", err)
	}

	return &http.Client{
		Timeout:       defaultTimeout,
		CheckRedirect: checkRedirect,
		Transport: &http.Transport{
			Proxy:           http.ProxyFromEnvironment,
			TLSClientConfig: tlsCfg,
			MaxIdleConns:    defaultMaxIdleConns,
			IdleConnTimeout: defaultIdleConnTimeout,
		},
	}, nil
}
