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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"

	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

// TLSClientConfig holds the per-output TLS settings of HTTP and TCP outputs.
type TLSClientConfig struct {
	CAFile             string `mapstructure:"ca_file"`
	CertFile           string `mapstructure:"cert_file"`
	KeyFile            string `mapstructure:"key_file"`
	ServerName         string `mapstructure:"server_name"`
	InsecureSkipVerify bool   `mapstructure:"insecure_skip_verify"`
}

// Validate checks TLS client settings for consistency and file existence.
func (c *TLSClientConfig) Validate() utils.ValidationErrors {
	var errs utils.ValidationErrors
	if c.CertFile != "" && c.KeyFile == "" {
		errs.Add("key_file", "is required when cert_file is set")
	}
	if c.KeyFile != "" && c.CertFile == "" {
		errs.Add("cert_file", "is required when key_file is set")
	}
	if c.CAFile != "" {
		errs.CheckFile("ca_file", c.CAFile)
	}
	if c.CertFile != "" {
		errs.CheckFile("cert_file", c.CertFile)
	}
	if c.KeyFile != "" {
		errs.CheckFile("key_file", c.KeyFile)
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

// TLSClientSchemaFields returns schema fields for the per-output tls: section.
func TLSClientSchemaFields() []output.SchemaField {
	return []output.SchemaField{
		{Name: "tls.insecure_skip_verify", Type: "bool", Default: false, Label: "Skip TLS Certificate Verification"},
		{Name: "tls.ca_file", Type: "string", Label: "CA Certificate File"},
		{Name: "tls.cert_file", Type: "string", Label: "Client Certificate File (mTLS)"},
		{Name: "tls.key_file", Type: "string", Label: "Client Key File (mTLS)"},
		{Name: "tls.server_name", Type: "string", Label: "Server Name Override"},
	}
}

// BuildTLSConfig creates a *tls.Config from per-output TLS settings.
// Its errors name the field, not the path or the OS error.
func BuildTLSConfig(cfg *TLSClientConfig) (*tls.Config, error) {
	tlsCfg := &tls.Config{
		InsecureSkipVerify: cfg.InsecureSkipVerify, //nolint:gosec // user-configurable TLS verification
		MinVersion:         tls.VersionTLS12,
	}

	if cfg.ServerName != "" {
		tlsCfg.ServerName = cfg.ServerName
	}

	if cfg.CAFile != "" {
		caCert, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, errors.New("tls.ca_file: cannot read file")
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, errors.New("tls.ca_file: no valid PEM certificate")
		}
		tlsCfg.RootCAs = pool
	}

	if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, errors.New("tls.cert_file, tls.key_file: cannot load the key pair")
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	return tlsCfg, nil
}
