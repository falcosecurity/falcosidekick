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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/utils"
)

func TestOptionalTLSDecodeAndValidate(t *testing.T) {
	for _, tc := range []struct {
		raw     map[string]any
		name    string
		wantErr string
		enabled bool
	}{
		{name: "absent", raw: map[string]any{}},
		{name: "enabled alone", raw: map[string]any{"tls": map[string]any{"enabled": true}}, enabled: true},
		{name: "enabled with settings", raw: map[string]any{"tls": map[string]any{"enabled": true, "server_name": "kafka.internal"}}, enabled: true},
		{name: "settings without enabled", raw: map[string]any{"tls": map[string]any{"server_name": "kafka.internal"}},
			wantErr: "tls.enabled: must be true when other tls settings are set"},
		{name: "settings with enabled false", raw: map[string]any{"tls": map[string]any{"enabled": false, "insecure_skip_verify": true}},
			wantErr: "tls.enabled: must be true when other tls settings are set"},
		{name: "client settings still checked", raw: map[string]any{"tls": map[string]any{"enabled": true, "cert_file": "/x"}},
			wantErr: "tls.key_file: is required when cert_file is set"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var cfg struct {
				TLS OptionalTLSConfig `mapstructure:"tls"`
			}
			require.NoError(t, DecodeDriverConfig(tc.raw, &cfg))
			var errs utils.ValidationErrors
			errs.Merge("tls", cfg.TLS.Validate())
			if tc.wantErr != "" {
				assert.Contains(t, errs.Error(), tc.wantErr)
				return
			}
			assert.Empty(t, errs)
			assert.Equal(t, tc.enabled, cfg.TLS.Enabled)
		})
	}
}

func TestOptionalTLSRefusesTheOldKey(t *testing.T) {
	var cfg struct {
		TLS OptionalTLSConfig `mapstructure:"tls"`
	}
	err := DecodeDriverConfig(map[string]any{"tls_enabled": true}, &cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tls_enabled")
}

func TestOptionalTLSBuild(t *testing.T) {
	disabled := OptionalTLSConfig{TLSClientConfig: TLSClientConfig{ServerName: "ignored"}}
	cfg, err := disabled.Build()
	require.NoError(t, err)
	assert.Nil(t, cfg, "no TLS unless enabled")

	enabled := OptionalTLSConfig{Enabled: true, TLSClientConfig: TLSClientConfig{ServerName: "redis.internal"}}
	cfg, err = enabled.Build()
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, "redis.internal", cfg.ServerName)

	broken := OptionalTLSConfig{Enabled: true, TLSClientConfig: TLSClientConfig{CAFile: "/nonexistent/ca.pem"}}
	_, err = broken.Build()
	require.EqualError(t, err, "tls.ca_file: file does not exist")
}

func TestOptionalTLSSchemaFields(t *testing.T) {
	fields := OptionalTLSSchemaFields()
	require.NotEmpty(t, fields)
	assert.Equal(t, "tls.enabled", fields[0].Name)
	assert.Equal(t, "bool", fields[0].Type)
	assert.Equal(t, false, fields[0].Default)
	assert.Equal(t, TLSClientSchemaFields(), fields[1:])
}
