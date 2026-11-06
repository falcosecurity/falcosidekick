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
	"fmt"
	"strings"
	"time"

	"github.com/falcosecurity/falcosidekick/internal/utils"
)

// Config holds Sidekick core configuration; changes require a restart.
type Config struct {
	TLS           *TLSConfig         `json:"tls,omitempty" mapstructure:"tls,omitempty"`
	LogFormat     LogFormat          `json:"log_format" mapstructure:"log_format"`
	LogLevel      LogLevel           `json:"log_level" mapstructure:"log_level"`
	ListenAddress string             `json:"listen_address" mapstructure:"listen_address"`
	Database      DatabaseConfig     `json:"database" mapstructure:"database"`
	Metrics       MetricsConfig      `json:"metrics" mapstructure:"metrics"`
	UI            UIConfig           `json:"ui" mapstructure:"ui"`
	Reload        ReloadConfig       `json:"reload" mapstructure:"reload"`
	Provisioning  ProvisioningConfig `json:"provisioning" mapstructure:"provisioning"`
	API           APIConfig          `json:"api" mapstructure:"api"`
	ListenPort    int                `json:"listen_port" mapstructure:"listen_port"`
}

// MetricsConfig controls the Prometheus metrics on /metrics.
type MetricsConfig struct {
	ExtraLabels []string `json:"extra_labels" mapstructure:"extra_labels"`
}

// Validate rejects extra labels that are invalid Prometheus label names or collide with another label.
func (c MetricsConfig) Validate() utils.ValidationErrors {
	var errs utils.ValidationErrors
	seen := map[string]string{"rule": "", "priority": "", "source": ""}
	for _, field := range c.ExtraLabels {
		label := MetricLabelName(field)
		if !validMetricLabel(label) {
			errs.Add("extra_labels", fmt.Sprintf("%q is not a valid label name", field))
			continue
		}
		if prev, ok := seen[label]; ok {
			if prev == "" {
				errs.Add("extra_labels", fmt.Sprintf("%q collides with a built-in label", field))
			} else {
				errs.Add("extra_labels", fmt.Sprintf("%q and %q map to the same label", prev, field))
			}
			continue
		}
		seen[label] = field
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

// MetricLabelName turns an output field name into a label name.
func MetricLabelName(field string) string { return strings.ReplaceAll(field, ".", "_") }

func validMetricLabel(name string) bool {
	if name == "" || strings.HasPrefix(name, "__") {
		return false
	}
	for i, r := range name {
		switch {
		case r == '_', r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

// APIConfig controls the management API.
type APIConfig struct {
	AllowWrites bool `json:"allow_writes" mapstructure:"allow_writes"`
}

// ProvisioningConfig controls how file provisioning and UI writes interact.
type ProvisioningConfig struct {
	AllowUIUpdates  bool `json:"allow_ui_updates" mapstructure:"allow_ui_updates"`
	DisableDeletion bool `json:"disable_deletion" mapstructure:"disable_deletion"`
}

// Validate checks core configuration; TLS files are checked by the config loader.
func (c *Config) Validate() utils.ValidationErrors {
	var errs utils.ValidationErrors

	if c.ListenPort < 1 || c.ListenPort > 65535 {
		errs.Add("listen_port", "must be 1-65535")
	}

	errs.Merge("", c.LogLevel.Validate())
	errs.Merge("", c.LogFormat.Validate())
	errs.Merge("database", c.Database.Validate())
	errs.Merge("ui", c.UI.Validate())
	errs.Merge("reload", c.Reload.Validate())
	errs.Merge("metrics", c.Metrics.Validate())

	if len(errs) > 0 {
		return errs
	}
	return nil
}

// LogLevel identifies a logging verbosity level.
type LogLevel string

// Supported log levels.
const (
	LogLevelTrace   LogLevel = "trace"
	LogLevelDebug   LogLevel = "debug"
	LogLevelInfo    LogLevel = "info"
	LogLevelWarning LogLevel = "warning"
	LogLevelError   LogLevel = "error"
)

// ValidLogLevels holds the set of accepted log level values.
var ValidLogLevels = map[LogLevel]bool{
	LogLevelTrace: true, LogLevelDebug: true, LogLevelInfo: true,
	LogLevelWarning: true, LogLevelError: true,
}

// Validate checks the log level for correctness.
func (l LogLevel) Validate() utils.ValidationErrors {
	var errs utils.ValidationErrors
	if !ValidLogLevels[l] {
		errs.Add("log_level", "must be trace/debug/info/warning/error")
	}
	return errs
}

// LogFormat identifies a log output format.
type LogFormat string

// Supported log formats.
const (
	LogFormatJSON LogFormat = "json"
	LogFormatText LogFormat = "text"
)

// ValidLogFormats holds the set of accepted log format values.
var ValidLogFormats = map[LogFormat]bool{
	LogFormatText: true, LogFormatJSON: true,
}

// Validate checks the log format for correctness.
func (f LogFormat) Validate() utils.ValidationErrors {
	var errs utils.ValidationErrors
	if !ValidLogFormats[f] {
		errs.Add("log_format", "must be text/json")
	}
	return errs
}

// TLSConfig holds server-side TLS settings for the HTTP listener.
type TLSConfig struct {
	CertFile   string `json:"cert_file" mapstructure:"cert_file"`
	KeyFile    string `json:"key_file" mapstructure:"key_file"`
	CACertFile string `json:"ca_file" mapstructure:"ca_file"`
	Enabled    bool   `json:"enabled" mapstructure:"enabled"`
	MutualTLS  bool   `json:"mutual_tls" mapstructure:"mutual_tls"`
}

// UIConfig holds UI settings.
type UIConfig struct {
	EventSource string `json:"event_source" mapstructure:"event_source"`
	Enabled     bool   `json:"enabled" mapstructure:"enabled"`
}

// Validate checks the UI configuration for correctness.
func (c *UIConfig) Validate() utils.ValidationErrors {
	var errs utils.ValidationErrors
	if c.Enabled && c.EventSource == "" {
		errs.Add("event_source", "is required when UI is enabled")
	}
	return errs
}

// DatabaseBackend identifies the database implementation.
type DatabaseBackend string

// Supported database backends.
const (
	DatabaseInMemory DatabaseBackend = "inmemory"
	DatabaseSQLite   DatabaseBackend = "sqlite"
	DatabasePostgres DatabaseBackend = "postgres"
)

// ValidDatabaseBackends holds the set of accepted database backends.
var ValidDatabaseBackends = map[DatabaseBackend]bool{
	DatabaseInMemory: true, DatabaseSQLite: true, DatabasePostgres: true,
}

// DatabaseConfig holds database backend selection.
type DatabaseConfig struct {
	Backend DatabaseBackend `json:"backend" mapstructure:"backend"`
}

// Validate checks the database settings for correctness.
func (c *DatabaseConfig) Validate() utils.ValidationErrors {
	var errs utils.ValidationErrors
	if !ValidDatabaseBackends[c.Backend] {
		errs.Add("backend", "must be inmemory/sqlite/postgres")
	}
	return errs
}

// ReloadConfig holds hot-reload settings for output configuration.
type ReloadConfig struct {
	PollInterval  time.Duration `json:"poll_interval" mapstructure:"poll_interval"`
	RetireTimeout time.Duration `json:"retire_timeout" mapstructure:"retire_timeout"`
}

// Validate checks reload settings for correctness.
func (c *ReloadConfig) Validate() utils.ValidationErrors {
	var errs utils.ValidationErrors
	if c.PollInterval < 0 {
		errs.Add("poll_interval", "must be non-negative")
	}
	if c.RetireTimeout < 0 {
		errs.Add("retire_timeout", "must be non-negative")
	}
	return errs
}
