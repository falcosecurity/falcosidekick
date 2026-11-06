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
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const sentinel = "s3cret-sentinel"

func TestValidatorsNeverEchoValues(t *testing.T) {
	tests := []struct {
		run  func() string
		name string
		want string
	}{
		{
			name: "url parse failure",
			run:  func() string { return ValidateOrigin("https://u:" + sentinel + "@ho st/x").Error() },
			want: ": invalid URL",
		},
		{
			name: "url without host",
			run:  func() string { return ValidateOrigin("nohost?token=" + sentinel).Error() },
			want: ": must include scheme and host (e.g. https://host:port)",
		},
		{
			name: "url with unsupported scheme",
			run:  func() string { return ValidateOrigin("ftp://u:" + sentinel + "@host/x").Error() },
			want: ": scheme must be http or https",
		},
		{
			name: "endpoint",
			run:  func() string { return ValidateEndpoint("/a b/" + sentinel).Error() },
			want: ": must be a valid path starting with / (e.g. /api/v1)",
		},
		{
			name: "origins parse failure keeps index",
			run:  func() string { return ValidateOrigins([]string{"http://ok", "http://[" + sentinel}).Error() },
			want: ": entry [1] invalid URL",
		},
		{
			name: "brokers without port keep index",
			run:  func() string { return ValidateBrokers([]string{sentinel}).Error() },
			want: ": entry [0] must be host:port without a scheme (e.g. server.example:9092)",
		},
		{
			name: "http hosts unsupported scheme keeps index",
			run:  func() string { return ValidateOrigins([]string{"ftp://" + sentinel}).Error() },
			want: ": entry [0] scheme must be http or https",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.run()
			assert.Equal(t, tc.want, got)
			assert.NotContains(t, got, sentinel)
		})
	}
}

func TestSchemeAcceptance(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		httpOK   bool
		brokerOK bool
	}{
		{name: "http", value: "http://host:9200", httpOK: true},
		{name: "https", value: "https://host", httpOK: true},
		{name: "uppercase", value: "HTTPS://host", httpOK: true},
		{name: "ftp", value: "ftp://host"},
		{name: "kafka scheme", value: "kafka://broker:9092"},
		{name: "no scheme", value: "host"},
		{name: "host and port", value: "broker:9092", brokerOK: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.httpOK, len(ValidateOrigin(tc.value)) == 0, "ValidateOrigin")
			assert.Equal(t, tc.httpOK, len(ValidateOrigins([]string{tc.value})) == 0, "ValidateOrigins")
			assert.Equal(t, tc.brokerOK, len(ValidateBrokers([]string{tc.value})) == 0, "ValidateBrokers")
		})
	}
}

type decodeTarget struct {
	Headers map[string]ValueSources `mapstructure:"headers"`
	Name    string                  `mapstructure:"name"`
	Nested  struct {
		Value string `mapstructure:"value"`
	} `mapstructure:"nested"`
	Timeout time.Duration `mapstructure:"timeout"`
	Count   int           `mapstructure:"count"`
	Enabled bool          `mapstructure:"enabled"`
}

func TestDecodeDriverConfigErrorsNeverEchoValues(t *testing.T) {
	tests := []struct {
		raw  map[string]any
		name string
		want string
	}{
		{name: "map into string", raw: map[string]any{"name": map[string]any{"a": sentinel}}, want: "name: invalid type, expected string"},
		{name: "invalid duration", raw: map[string]any{"timeout": sentinel}, want: "timeout: invalid value"},
		{name: "invalid number", raw: map[string]any{"count": sentinel}, want: "count: invalid value"},
		{name: "invalid bool", raw: map[string]any{"enabled": sentinel}, want: "enabled: invalid value"},
		{name: "string into struct", raw: map[string]any{"nested": sentinel}, want: "nested: invalid type, expected map"},
		{name: "unknown property", raw: map[string]any{"headers": map[string]any{"X-A": map[string]any{"oops": sentinel}}}, want: "headers[X-A]: unknown property"},
		{name: "header values wrong shape", raw: map[string]any{"headers": map[string]any{"X-A": map[string]any{"secrets": sentinel}}}, want: "headers[X-A]: secrets: must be a list of strings"},
		{name: "unknown key keeps its name", raw: map[string]any{"unknown_key": sentinel}, want: "unknown keys: unknown_key"},
		{name: "nested unknown key", raw: map[string]any{"nested": map[string]any{"other": sentinel}}, want: "nested: unknown keys: other"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var target decodeTarget
			err := DecodeDriverConfig(tc.raw, &target)
			require.Error(t, err)
			assert.Equal(t, tc.want, err.Error())
			assert.NotContains(t, err.Error(), sentinel)
		})
	}
}

func TestDecodeDriverConfigReportsEveryFieldInStableOrder(t *testing.T) {
	var target decodeTarget
	err := DecodeDriverConfig(map[string]any{"timeout": sentinel, "count": sentinel}, &target)
	require.Error(t, err)
	assert.Equal(t, "count: invalid value; timeout: invalid value", err.Error())
}
