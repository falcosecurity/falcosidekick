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
	"testing"

	"github.com/stretchr/testify/assert"
)

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
		Database:      DatabaseConfig{Backend: DatabaseInMemory},
	}
	assert.Empty(t, cfg.Validate())
}

func TestConfigValidateInvalidPort(t *testing.T) {
	cfg := Config{
		ListenPort: 0,
		LogLevel:   LogLevelInfo,
		LogFormat:  LogFormatText,
		Database:   DatabaseConfig{Backend: DatabaseInMemory},
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

func TestDatabaseConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		backend DatabaseBackend
		wantErr bool
	}{
		{"memory", DatabaseInMemory, false},
		{"sqlite", DatabaseSQLite, false},
		{"postgres", DatabasePostgres, false},
		{"invalid", DatabaseBackend("redis"), true},
		{"empty", DatabaseBackend(""), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DatabaseConfig{Backend: tt.backend}
			errs := cfg.Validate()
			if tt.wantErr {
				assert.NotEmpty(t, errs)
			} else {
				assert.Empty(t, errs)
			}
		})
	}
}
