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
	"path/filepath"
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
	Management    ManagementConfig   `json:"management" mapstructure:"management"`
	UI            UIConfig           `json:"ui" mapstructure:"ui"`
	API           APIConfig          `json:"api" mapstructure:"api"`
	Metrics       MetricsConfig      `json:"metrics" mapstructure:"metrics"`
	Database      DatabaseConfig     `json:"database" mapstructure:"database"`
	Reload        ReloadConfig       `json:"reload" mapstructure:"reload"`
	ListenPort    int                `json:"listen_port" mapstructure:"listen_port"`
	Provisioning  ProvisioningConfig `json:"provisioning" mapstructure:"provisioning"`
	// ShutdownDelay is how long ingestion keeps accepting events after SIGTERM while /readyz fails,
	// so Kubernetes stops routing to the pod before the listener closes.
	ShutdownDelay time.Duration `json:"shutdown_delay" mapstructure:"shutdown_delay"`
}

// MetricsConfig controls the Prometheus metrics on /metrics.
type MetricsConfig struct {
	ExtraLabels []string `json:"extra_labels" mapstructure:"extra_labels"`
	// MaxLabelValues caps the distinct values of each label taken from events; later values become "other".
	MaxLabelValues int `json:"max_label_values" mapstructure:"max_label_values"`
}

// Validate rejects extra labels that are invalid Prometheus label names or collide with another label.
func (c MetricsConfig) Validate() utils.ValidationErrors {
	var errs utils.ValidationErrors
	if c.MaxLabelValues < 1 {
		errs.Add("max_label_values", "must be at least 1")
	}
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

// ManagementConfig is the listener of the API and the UI, apart from event ingestion.
type ManagementConfig struct {
	ListenAddress string `json:"listen_address" mapstructure:"listen_address"`
	ListenPort    int    `json:"listen_port" mapstructure:"listen_port"`
}

// Validate checks the management listener.
func (c ManagementConfig) Validate() utils.ValidationErrors {
	var errs utils.ValidationErrors
	// Empty would listen on every interface: the unauthenticated API must be opened explicitly.
	if c.ListenAddress == "" {
		errs.Add("listen_address", `is required ("::" for every interface)`)
	}
	if c.ListenPort < 1 || c.ListenPort > 65535 {
		errs.Add("listen_port", "must be 1-65535")
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

// APIConfig controls the management API.
type APIConfig struct {
	// SecretDirs holds the directories an output file path sent through the API must resolve into.
	// Empty refuses every file path sent through the API; output files are not restricted.
	SecretDirs  []string `json:"secret_dirs" mapstructure:"secret_dirs"`
	AllowWrites bool     `json:"allow_writes" mapstructure:"allow_writes"`
}

// Validate requires absolute secret directories.
func (c APIConfig) Validate() utils.ValidationErrors {
	var errs utils.ValidationErrors
	for _, dir := range c.SecretDirs {
		if !filepath.IsAbs(dir) {
			errs.Add("secret_dirs", fmt.Sprintf("%q must be an absolute path", dir))
		}
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

// ProvisioningConfig controls how file provisioning and UI writes interact.
type ProvisioningConfig struct {
	AllowUIUpdates bool `json:"allow_ui_updates" mapstructure:"allow_ui_updates"`
}

// Validate checks core configuration; TLS files are checked by the config loader.
func (c *Config) Validate() utils.ValidationErrors {
	var errs utils.ValidationErrors

	if c.ListenPort < 1 || c.ListenPort > 65535 {
		errs.Add("listen_port", "must be 1-65535")
	}
	if c.ShutdownDelay < 0 {
		errs.Add("shutdown_delay", "must be >= 0")
	}
	errs.Merge("management", c.Management.Validate())
	if c.Management.ListenPort == c.ListenPort {
		errs.Add("management.listen_port", "must differ from listen_port")
	}

	errs.Merge("", c.LogLevel.Validate())
	errs.Merge("", c.LogFormat.Validate())
	errs.Merge("database", c.Database.Validate())
	errs.Merge("ui", c.UI.Validate())
	errs.Merge("reload", c.Reload.Validate())
	errs.Merge("metrics", c.Metrics.Validate())
	errs.Merge("api", c.API.Validate())

	if len(errs) > 0 {
		return errs
	}
	return nil
}

// LogLevel identifies a logging verbosity level.
type LogLevel string

// Supported log levels, named as log/slog names them.
const (
	LogLevelDebug LogLevel = "debug"
	LogLevelInfo  LogLevel = "info"
	LogLevelWarn  LogLevel = "warn"
	LogLevelError LogLevel = "error"
)

// ValidLogLevels holds the set of accepted log level values.
var ValidLogLevels = map[LogLevel]bool{
	LogLevelDebug: true, LogLevelInfo: true, LogLevelWarn: true, LogLevelError: true,
}

// Validate checks the log level for correctness.
func (l LogLevel) Validate() utils.ValidationErrors {
	var errs utils.ValidationErrors
	if !ValidLogLevels[l] {
		errs.Add("log_level", "must be debug/info/warn/error")
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

// Persistent reports whether the backend keeps what it stores across restarts.
func (b DatabaseBackend) Persistent() bool { return b == DatabaseSQLite || b == DatabasePostgres }

// DatabaseConfig selects where outputs and the UI layout are stored.
type DatabaseConfig struct {
	Backend  DatabaseBackend `json:"backend" mapstructure:"backend"`
	SQLite   SQLiteConfig    `json:"sqlite" mapstructure:"sqlite"`
	Postgres PostgresConfig  `json:"postgres" mapstructure:"postgres"`
	// ConnectTimeout bounds opening the database and applying its migrations at startup.
	ConnectTimeout time.Duration `json:"connect_timeout" mapstructure:"connect_timeout"`
}

// SQLiteConfig holds the sqlite database file, for one Sidekick instance.
type SQLiteConfig struct {
	Path string `json:"path" mapstructure:"path"`
}

// PostgresSSLMode is the libpq sslmode of the postgres connection.
type PostgresSSLMode string

// Supported postgres sslmodes.
const (
	PostgresSSLDisable    PostgresSSLMode = "disable"
	PostgresSSLRequire    PostgresSSLMode = "require"
	PostgresSSLVerifyCA   PostgresSSLMode = "verify-ca"
	PostgresSSLVerifyFull PostgresSSLMode = "verify-full"
)

// PostgresConfig holds the postgres connection that several Sidekick instances can share.
type PostgresConfig struct {
	Host     string `json:"host" mapstructure:"host"`
	Database string `json:"database" mapstructure:"database"`
	User     string `json:"user" mapstructure:"user"`
	// Password is masked by GET /api/v1/config; PasswordFile reads it from a file instead.
	Password     string          `json:"password,omitempty" mapstructure:"password"`
	PasswordFile string          `json:"password_file,omitempty" mapstructure:"password_file"`
	SSLMode      PostgresSSLMode `json:"sslmode" mapstructure:"sslmode"`
	TLS          PostgresTLS     `json:"tls" mapstructure:"tls"`
	Port         int             `json:"port" mapstructure:"port"`
	// MaxConnections caps the connections this instance opens.
	MaxConnections int `json:"max_connections" mapstructure:"max_connections"`
	// PollInterval is how often an instance checks the stored outputs for changes it was not notified of.
	PollInterval time.Duration `json:"poll_interval" mapstructure:"poll_interval"`
}

// PostgresTLS holds the CA that verifies the postgres server with sslmode verify-ca or verify-full.
type PostgresTLS struct {
	CAFile string `json:"ca_file,omitempty" mapstructure:"ca_file"`
}

// Validate checks the settings of the selected backend; the others are ignored.
func (c *DatabaseConfig) Validate() utils.ValidationErrors {
	var errs utils.ValidationErrors
	if !ValidDatabaseBackends[c.Backend] {
		errs.Add("backend", "must be inmemory/sqlite/postgres")
	}
	if c.ConnectTimeout <= 0 {
		errs.Add("connect_timeout", "must be > 0")
	}
	switch c.Backend {
	case DatabaseInMemory:
	case DatabaseSQLite:
		if c.SQLite.Path == "" {
			errs.Add("sqlite.path", "must be specified")
		}
	case DatabasePostgres:
		errs.Merge("postgres", c.Postgres.Validate())
	}
	return errs
}

// Validate checks the postgres settings.
func (c *PostgresConfig) Validate() utils.ValidationErrors {
	var errs utils.ValidationErrors
	if c.Host == "" {
		errs.Add("host", "must be specified")
	}
	if c.Database == "" {
		errs.Add("database", "must be specified")
	}
	if c.User == "" {
		errs.Add("user", "must be specified")
	}
	if c.Port < 1 || c.Port > 65535 {
		errs.Add("port", "must be 1-65535")
	}
	if c.Password != "" && c.PasswordFile != "" {
		errs.Add("password", "set password or password_file, not both")
	}
	switch c.SSLMode {
	case PostgresSSLVerifyCA, PostgresSSLVerifyFull:
	case PostgresSSLDisable, PostgresSSLRequire:
		if c.TLS.CAFile != "" {
			errs.Add("tls.ca_file", "is used only with sslmode verify-ca or verify-full")
		}
	default:
		errs.Add("sslmode", "must be disable/require/verify-ca/verify-full")
	}
	if c.MaxConnections < 1 {
		errs.Add("max_connections", "must be >= 1")
	}
	if c.PollInterval <= 0 {
		errs.Add("poll_interval", "must be > 0")
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
