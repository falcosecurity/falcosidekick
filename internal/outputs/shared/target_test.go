// Copyright (C) 2026 The Falco Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
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
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain/output"
)

func TestHTTPTargetConfigValidate(t *testing.T) {
	const sentinel = "s3cret-sentinel"
	tests := []struct {
		name string
		want string
		cfg  HTTPTargetConfig
		opts HTTPTargetOptions
	}{
		{name: "minimal", cfg: HTTPTargetConfig{Host: "https://h"}},
		{name: "host required", want: "host: is required"},
		{name: "host with path", cfg: HTTPTargetConfig{Host: "https://h/" + sentinel}, want: "host: must be scheme, host and port only"},
		{name: "host with credentials", cfg: HTTPTargetConfig{Host: "https://u:" + sentinel + "@h"}, want: "host: must not include credentials"},
		{name: "base_path without slash", cfg: HTTPTargetConfig{Host: "https://h", BasePath: sentinel}, want: "base_path: must be a valid path"},
		{name: "base_path with query", cfg: HTTPTargetConfig{Host: "https://h", BasePath: "/a?t=" + sentinel}, want: "base_path: must be a valid path"},
		{name: "endpoint with query", cfg: HTTPTargetConfig{Host: "https://h", Endpoint: "/a?t=" + sentinel}, want: "endpoint: must be a valid path"},
		{name: "endpoint with fragment", cfg: HTTPTargetConfig{Host: "https://h", Endpoint: "/a#" + sentinel}, want: "endpoint: must be a valid path"},
		{name: "secret_endpoint with query", cfg: HTTPTargetConfig{Host: "https://h", SecretEndpoint: "/a?t=" + sentinel}, want: "secret_endpoint: must be a valid path"},
		{name: "exclusive", cfg: HTTPTargetConfig{Host: "https://h", Endpoint: "/a", SecretEndpoint: "/" + sentinel}, want: "endpoint: cannot be combined with secret_endpoint"},
		{
			name: "secret required", opts: HTTPTargetOptions{SecretEndpointRequired: true},
			cfg: HTTPTargetConfig{Host: "https://h"}, want: "secret_endpoint: is required",
		},
		{
			name: "public endpoint refused when secret required", opts: HTTPTargetOptions{SecretEndpointRequired: true},
			cfg: HTTPTargetConfig{Host: "https://h", Endpoint: "/a", SecretEndpoint: "/b"}, want: "endpoint: is not supported; use secret_endpoint",
		},
		{
			name: "driver routes refuse endpoint", opts: HTTPTargetOptions{DriverRoutes: true},
			cfg: HTTPTargetConfig{Host: "https://h", Endpoint: "/a"}, want: "endpoint: is not supported",
		},
		{
			name: "driver routes refuse secret_endpoint", opts: HTTPTargetOptions{DriverRoutes: true},
			cfg: HTTPTargetConfig{Host: "https://h", SecretEndpoint: "/a"}, want: "secret_endpoint: is not supported",
		},
		{
			name: "external hosts refuse host", opts: HTTPTargetOptions{ExternalHosts: true},
			cfg: HTTPTargetConfig{Host: "https://h"}, want: "host: is not supported; use hosts",
		},
		{name: "external hosts need no host", opts: HTTPTargetOptions{ExternalHosts: true}},
		{
			name: "reserved query param", opts: HTTPTargetOptions{ReservedQueryParams: []string{"pipeline"}},
			cfg:  HTTPTargetConfig{Host: "https://h", QueryParams: map[string]ValueSources{"pipeline": {Values: []string{"x"}}}},
			want: `query_params["pipeline"]: is set by the output`,
		},
		{
			name: "empty query param name",
			cfg:  HTTPTargetConfig{Host: "https://h", QueryParams: map[string]ValueSources{"": {Values: []string{"x"}}}},
			want: "query_params: parameter name must not be empty",
		},
		{
			name: "unreadable query file",
			cfg:  HTTPTargetConfig{Host: "https://h", QueryParams: map[string]ValueSources{"t": {Files: []string{"/nonexistent/" + sentinel}}}},
			want: `query_params["t"]: files[0]: cannot read query file`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := tt.cfg.Validate(&tt.opts)
			if tt.want == "" {
				assert.Empty(t, errs)
				return
			}
			assert.Contains(t, errs.Error(), tt.want)
			assert.NotContains(t, errs.Error(), sentinel)
		})
	}
}

func TestHTTPTargetConfigDefaults(t *testing.T) {
	cfg := HTTPTargetConfig{BasePath: "/gateway//"}
	require.Empty(t, cfg.Validate(&HTTPTargetOptions{DefaultHost: "https://default", DefaultEndpoint: "/push"}))
	assert.Equal(t, "https://default", cfg.Host)
	assert.Equal(t, "/gateway", cfg.BasePath)
	assert.Equal(t, "/push", cfg.Endpoint)

	root := HTTPTargetConfig{Host: "https://h", BasePath: "/", SecretEndpoint: "/s"}
	require.Empty(t, root.Validate(&HTTPTargetOptions{DefaultEndpoint: "/push"}))
	assert.Empty(t, root.BasePath)
	assert.Empty(t, root.Endpoint, "a default must not join a secret endpoint")
}

func TestHTTPTargetConfigURL(t *testing.T) {
	tests := []struct {
		query url.Values
		name  string
		route string
		want  string
		cfg   HTTPTargetConfig
	}{
		{name: "route", cfg: HTTPTargetConfig{}, route: "/a", want: "https://h/a"},
		{name: "empty route", cfg: HTTPTargetConfig{}, want: "https://h"},
		{name: "base path", cfg: HTTPTargetConfig{BasePath: "/gw"}, route: "/a", want: "https://h/gw/a"},
		{name: "keeps percent-encoding", cfg: HTTPTargetConfig{}, route: "/a%2Fb", want: "https://h/a%2Fb"},
		{
			name: "escapes and repeats",
			cfg: HTTPTargetConfig{QueryParams: map[string]ValueSources{
				"a b": {Values: []string{"1&2", "x y"}, Secrets: []string{"é=?"}},
			}},
			route: "/a", want: "https://h/a?a+b=1%262&a+b=x+y&a+b=%C3%A9%3D%3F",
		},
		{name: "driver query", cfg: HTTPTargetConfig{}, route: "/a", query: url.Values{"p": {"a&b"}}, want: "https://h/a?p=a%26b"},
		{
			name: "entry without values is omitted",
			cfg:  HTTPTargetConfig{QueryParams: map[string]ValueSources{"none": {}}}, route: "/a", want: "https://h/a",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.cfg.URL("https://h", tt.route, tt.query)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestHTTPTargetConfigURLDoesNotMutateDriverQuery(t *testing.T) {
	query := url.Values{"p": {"1"}}
	cfg := HTTPTargetConfig{QueryParams: map[string]ValueSources{"t": {Values: []string{"2"}}}}
	_, err := cfg.URL("https://h", "/a", query)
	require.NoError(t, err)
	assert.Equal(t, url.Values{"p": {"1"}}, query)
}

func TestHTTPTargetConfigRereadsQueryFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(path, []byte(" one\n"), 0o600))
	cfg := HTTPTargetConfig{Host: "https://h", Endpoint: "/a", QueryParams: map[string]ValueSources{"t": {Files: []string{path}}}}

	got, err := cfg.DeliveryURL()
	require.NoError(t, err)
	assert.Equal(t, "https://h/a?t=one", got)

	require.NoError(t, os.WriteFile(path, []byte("two"), 0o600))
	got, err = cfg.DeliveryURL()
	require.NoError(t, err)
	assert.Equal(t, "https://h/a?t=two", got)

	require.NoError(t, os.Remove(path))
	_, err = cfg.DeliveryURL()
	require.EqualError(t, err, `query_params["t"]: files[0]: cannot read query file`)
	assert.Contains(t, WrapDeliveryError("webhook", "target", err).Error(), "webhook target: cannot resolve target")
}

func TestHTTPTargetConfigURLRejectsBrokenAddress(t *testing.T) {
	const sentinel = "s3cret-sentinel"
	cfg := HTTPTargetConfig{BasePath: "/" + sentinel + "%zz"}
	_, err := cfg.URL("https://h", "/a", nil)
	require.EqualError(t, err, "invalid endpoint address")
}

func TestHTTPTargetSchemaFields(t *testing.T) {
	names := func(opts HTTPTargetOptions) map[string]output.SchemaField {
		fields := map[string]output.SchemaField{}
		for _, field := range HTTPTargetSchemaFields(&opts) {
			fields[field.Name] = field
		}
		return fields
	}

	public := names(HTTPTargetOptions{DefaultEndpoint: "/push"})
	assert.True(t, public["host"].Required)
	assert.Equal(t, "/push", public["endpoint"].Default)
	assert.True(t, public["secret_endpoint"].Secret)
	assert.False(t, public["secret_endpoint"].Required)
	assert.False(t, public["base_path"].Secret)
	entries := map[string]bool{}
	for _, field := range public["query_params"].EntryFields {
		entries[field.Name] = field.Secret
	}
	assert.Equal(t, map[string]bool{"values": false, "secrets": true, "files": false}, entries)

	secret := names(HTTPTargetOptions{DefaultHost: "https://d", SecretEndpointRequired: true})
	assert.False(t, secret["host"].Required)
	assert.Equal(t, "https://d", secret["host"].Default)
	assert.NotContains(t, secret, "endpoint")
	assert.True(t, secret["secret_endpoint"].Required)

	driver := names(HTTPTargetOptions{DriverRoutes: true})
	assert.NotContains(t, driver, "endpoint")
	assert.NotContains(t, driver, "secret_endpoint")

	assert.NotContains(t, names(HTTPTargetOptions{ExternalHosts: true}), "host")
}
