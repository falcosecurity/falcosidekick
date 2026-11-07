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
	"context"
	"crypto/tls"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildHTTPClientDefault(t *testing.T) {
	cfg := &HTTPConfig{}
	client, _ := BuildHTTPClient(cfg)

	require.NotNil(t, client)
	assert.Equal(t, defaultTimeout, client.Timeout)

	transport, ok := client.Transport.(*http.Transport)
	require.True(t, ok)
	assert.False(t, transport.TLSClientConfig.InsecureSkipVerify)
}

func TestBuildHTTPClientInsecure(t *testing.T) {
	cfg := &HTTPConfig{TLS: TLSClientConfig{InsecureSkipVerify: true}}
	client, _ := BuildHTTPClient(cfg)

	transport, ok := client.Transport.(*http.Transport)
	require.True(t, ok)
	assert.True(t, transport.TLSClientConfig.InsecureSkipVerify)
}

func TestBuildHTTPClientTLSVersion(t *testing.T) {
	cfg := &HTTPConfig{}
	client, _ := BuildHTTPClient(cfg)

	transport, ok := client.Transport.(*http.Transport)
	require.True(t, ok)
	assert.Equal(t, uint16(tls.VersionTLS12), transport.TLSClientConfig.MinVersion)
}

// A username alone still turns on basic auth, which would replace the bearer token.
func TestHTTPConfigRefusesBearerWithBasicAuth(t *testing.T) {
	for _, cfg := range []HTTPConfig{
		{BearerToken: "t", Username: "u"},
		{BearerToken: "t", Password: "p"},
		{BearerToken: "t", Username: "u", Password: "p"},
	} {
		errs := cfg.Validate()
		require.Len(t, errs, 1)
		assert.Contains(t, errs[0].Error(), "cannot use both bearer_token and basic auth")
	}
	assert.Empty(t, (&HTTPConfig{BearerToken: "t"}).Validate())
	assert.Empty(t, (&HTTPConfig{Username: "u", Password: "p"}).Validate())
}

func TestApplyHeaders(t *testing.T) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com", http.NoBody)
	require.NoError(t, err)

	require.NoError(t, ApplyHeaders(req, map[string]ValueSources{
		"X-Custom": {Values: []string{"value"}},
		"X-Other":  {Values: []string{"other"}},
	}))

	assert.Equal(t, "value", req.Header.Get("X-Custom"))
	assert.Equal(t, "other", req.Header.Get("X-Other"))
}

func TestApplyHeadersNilMap(t *testing.T) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com", http.NoBody)
	require.NoError(t, err)

	require.NoError(t, ApplyHeaders(req, nil))
	assert.Empty(t, req.Header.Get("X-Custom"))
}

func TestHTTPConfigSchemaFields(t *testing.T) {
	fields := HTTPConfigSchemaFields()

	require.NotEmpty(t, fields, "schema fields must not be empty")

	names := make(map[string]bool, len(fields))
	for _, f := range fields {
		names[f.Name] = true
	}

	assert.True(t, names["username"], "must include username field")
	assert.True(t, names["password"], "must include password field")
	assert.True(t, names["bearer_token"], "must include bearer_token field")
	assert.True(t, names["headers"], "must include headers field")
	assert.True(t, names["tls.insecure_skip_verify"], "must include insecure_skip_verify field")

	for _, f := range fields {
		if f.Name == "password" || f.Name == "bearer_token" {
			assert.True(t, f.Secret, "%s must be marked as secret", f.Name)
		}
		if f.Name == "headers" {
			assert.False(t, f.Secret, "headers must not introduce headers_file")
			require.Len(t, f.EntryFields, 3)
			for i, name := range []string{"values", "secrets", "files"} {
				assert.Equal(t, name, f.EntryFields[i].Name)
				assert.Equal(t, "string[]", f.EntryFields[i].Type)
				assert.Equal(t, name == "secrets", f.EntryFields[i].Secret)
			}
		}
	}
}
