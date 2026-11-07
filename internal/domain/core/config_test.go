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

package core

import (
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMetricsConfigValidate(t *testing.T) {
	tests := []struct {
		name      string
		wantErr   string
		labels    []string
		maxValues int
	}{
		{name: "none"},
		{name: "field names", labels: []string{"k8s.ns.name", "proc.name", "container_id"}},
		{name: "invalid character", labels: []string{"evt.arg[0]"}, wantErr: "not a valid label name"},
		{name: "leading digit", labels: []string{"1field"}, wantErr: "not a valid label name"},
		{name: "reserved prefix", labels: []string{"__name"}, wantErr: "not a valid label name"},
		{name: "empty", labels: []string{""}, wantErr: "not a valid label name"},
		{name: "built-in label", labels: []string{"rule"}, wantErr: "collides with a built-in label"},
		{name: "same label twice", labels: []string{"k8s.ns.name", "k8s_ns_name"}, wantErr: "map to the same label"},
		{name: "no label values", maxValues: -1, wantErr: "max_label_values: must be at least 1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			maxValues := tt.maxValues
			if maxValues == 0 {
				maxValues = 1000
			}
			errs := MetricsConfig{ExtraLabels: tt.labels, MaxLabelValues: maxValues}.Validate()
			if tt.wantErr == "" {
				assert.Empty(t, errs)
				return
			}
			assert.Contains(t, errs.Error(), tt.wantErr)
		})
	}
}

func TestLogLevelValidate(t *testing.T) {
	tests := []struct {
		name    string
		level   LogLevel
		wantErr bool
	}{
		{"trace", LogLevelTrace, false},
		{"debug", LogLevelDebug, false},
		{"info", LogLevelInfo, false},
		{"warning", LogLevelWarning, false},
		{"error", LogLevelError, false},
		{"invalid", LogLevel("invalid"), true},
		{"empty", LogLevel(""), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := tt.level.Validate()
			if tt.wantErr {
				assert.NotEmpty(t, errs)
			} else {
				assert.Empty(t, errs)
			}
		})
	}
}

func TestLogFormatValidate(t *testing.T) {
	tests := []struct {
		name    string
		format  LogFormat
		wantErr bool
	}{
		{"text", LogFormatText, false},
		{"json", LogFormatJSON, false},
		{"invalid", LogFormat("invalid"), true},
		{"empty", LogFormat(""), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := tt.format.Validate()
			if tt.wantErr {
				assert.NotEmpty(t, errs)
			} else {
				assert.Empty(t, errs)
			}
		})
	}
}

func TestUIConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     UIConfig
		wantErr bool
	}{
		{"disabled", UIConfig{Enabled: false}, false},
		{"enabled with backend", UIConfig{Enabled: true, EventSource: "memory"}, false},
		{"enabled no backend", UIConfig{Enabled: true, EventSource: ""}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := tt.cfg.Validate()
			if tt.wantErr {
				assert.NotEmpty(t, errs)
			} else {
				assert.Empty(t, errs)
			}
		})
	}
}

func TestConfigValidateValid(t *testing.T) {
	cfg := Config{
		ListenAddress: "0.0.0.0",
		ListenPort:    2801,
		LogLevel:      LogLevelInfo,
		LogFormat:     LogFormatText,
		Database:      DatabaseConfig{Backend: DatabaseInMemory, ConnectTimeout: time.Second},
		Metrics:       MetricsConfig{MaxLabelValues: 1000},
		Management:    ManagementConfig{ListenAddress: "127.0.0.1", ListenPort: 2802},
	}
	assert.Empty(t, cfg.Validate())
}

func TestConfigValidateManagementPort(t *testing.T) {
	for _, tc := range []struct {
		want string
		port int
	}{
		{port: 0, want: "management.listen_port: must be 1-65535"},
		{port: 65536, want: "management.listen_port: must be 1-65535"},
		{port: 2801, want: "management.listen_port: must differ from listen_port"},
		{port: 2802},
	} {
		t.Run(strconv.Itoa(tc.port), func(t *testing.T) {
			cfg := Config{
				ListenPort: 2801,
				LogLevel:   LogLevelInfo,
				LogFormat:  LogFormatText,
				Database:   DatabaseConfig{Backend: DatabaseInMemory, ConnectTimeout: time.Second},
				Metrics:    MetricsConfig{MaxLabelValues: 1000},
				Management: ManagementConfig{ListenAddress: "127.0.0.1", ListenPort: tc.port},
			}
			errs := cfg.Validate()
			if tc.want == "" {
				assert.Empty(t, errs)
				return
			}
			require.Len(t, errs, 1)
			assert.Contains(t, errs[0].Error(), tc.want)
		})
	}
}

func TestManagementConfigRefusesEmptyAddress(t *testing.T) {
	errs := ManagementConfig{ListenPort: 2802}.Validate()
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Error(), "listen_address: is required (0.0.0.0 for every interface)")
	assert.Empty(t, ManagementConfig{ListenAddress: "0.0.0.0", ListenPort: 2802}.Validate())
}

func TestAPIConfigValidateSecretDirs(t *testing.T) {
	assert.Empty(t, APIConfig{}.Validate())
	assert.Empty(t, APIConfig{SecretDirs: []string{"/run/secrets"}}.Validate())
	errs := APIConfig{SecretDirs: []string{"/run/secrets", "secrets"}}.Validate()
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Error(), `secret_dirs: "secrets" must be an absolute path`)
}

func TestConfigValidateInvalidPort(t *testing.T) {
	cfg := Config{
		ListenPort: 0,
		LogLevel:   LogLevelInfo,
		LogFormat:  LogFormatText,
		Database:   DatabaseConfig{Backend: DatabaseInMemory, ConnectTimeout: time.Second},
	}
	assert.NotEmpty(t, cfg.Validate())
}

func TestConfigValidateMultipleErrors(t *testing.T) {
	cfg := Config{
		ListenPort: -1,
		LogLevel:   "invalid",
		LogFormat:  "invalid",
		Database:   DatabaseConfig{Backend: "invalid"},
	}
	errs := cfg.Validate()
	assert.True(t, len(errs) >= 4)
}
