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

	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

// OptionalTLSConfig is the tls: section of TCP outputs that connect in clear text unless tls.enabled is set.
type OptionalTLSConfig struct {
	TLSClientConfig `mapstructure:",squash"`
	Enabled         bool `mapstructure:"enabled"`
}

// Validate refuses TLS settings without enabled: they would otherwise be ignored and the output would
// connect in clear text. Field names are relative to the tls: section.
func (c *OptionalTLSConfig) Validate() utils.ValidationErrors {
	errs := c.TLSClientConfig.Validate()
	if !c.Enabled && c.TLSClientConfig != (TLSClientConfig{}) {
		errs.Add("enabled", "must be true when other tls settings are set")
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

// Build returns nil when TLS is not enabled.
func (c *OptionalTLSConfig) Build() (*tls.Config, error) {
	if !c.Enabled {
		return nil, nil
	}
	return BuildTLSConfig(&c.TLSClientConfig)
}

// OptionalTLSSchemaFields returns tls.enabled followed by the per-output tls: fields.
func OptionalTLSSchemaFields() []output.SchemaField {
	return append([]output.SchemaField{
		{
			Name: "tls.enabled", Type: "bool", Default: false, Label: "Enable TLS",
			Description: "Connects over TLS. The other `tls` settings are refused unless this is set.",
		},
	}, TLSClientSchemaFields()...)
}
