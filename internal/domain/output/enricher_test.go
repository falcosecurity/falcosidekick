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

package output

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEnricherConfigValidateValid(t *testing.T) {
	cfg := EnricherConfig{
		TruncateEventThreshold: 4096,
		TruncateFieldThreshold: 512,
	}
	assert.Empty(t, cfg.Validate())
}

func TestEnricherConfigValidateNegativeEventThreshold(t *testing.T) {
	cfg := EnricherConfig{TruncateEventThreshold: -1}
	assert.NotEmpty(t, cfg.Validate())
}

func TestEnricherConfigValidateTooSmallFieldThreshold(t *testing.T) {
	cfg := EnricherConfig{
		TruncateEventThreshold: 4096,
		TruncateFieldThreshold: 3,
	}
	assert.NotEmpty(t, cfg.Validate())
}

func TestEnricherConfigValidateDisabledTruncation(t *testing.T) {
	cfg := EnricherConfig{
		TruncateEventThreshold: 0,
		TruncateFieldThreshold: 0,
	}
	assert.Empty(t, cfg.Validate())
}

func TestEnricherConfigValidateZeroThresholds(t *testing.T) {
	cfg := EnricherConfig{}
	assert.Empty(t, cfg.Validate())
}

func TestRedactionConfigValidate(t *testing.T) {
	valid := RedactionConfig{Enabled: true, BuiltinRules: true, Mask: "[REDACTED]"}
	tests := []struct {
		name    string
		mutate  func(*RedactionConfig)
		wantErr string
	}{
		{name: "builtin only", mutate: func(*RedactionConfig) {}},
		{name: "disabled is not checked", mutate: func(c *RedactionConfig) { c.Enabled = false; c.Mask = "" }},
		{name: "valid rule", mutate: func(c *RedactionConfig) {
			c.Rules = []RedactionRule{{Name: "pg", Pattern: `postgresql://[^:/]+:([^@]+)@`, Keep: 2}}
		}},
		{name: "empty mask", mutate: func(c *RedactionConfig) { c.Mask = "" }, wantErr: "redaction.mask"},
		{name: "nothing to redact", mutate: func(c *RedactionConfig) { c.BuiltinRules = false }, wantErr: "nothing would be redacted"},
		{name: "rule without name", mutate: func(c *RedactionConfig) {
			c.Rules = []RedactionRule{{Pattern: "x"}}
		}, wantErr: "redaction.rules[0].name"},
		{name: "rule without pattern", mutate: func(c *RedactionConfig) {
			c.Rules = []RedactionRule{{Name: "r"}}
		}, wantErr: "redaction.rules[0].pattern"},
		{name: "invalid pattern", mutate: func(c *RedactionConfig) {
			c.Rules = []RedactionRule{{Name: "r", Pattern: "(unclosed"}}
		}, wantErr: "redaction.rules[0].pattern"},
		{name: "negative keep", mutate: func(c *RedactionConfig) {
			c.Rules = []RedactionRule{{Name: "r", Pattern: "x", Keep: -1}}
		}, wantErr: "redaction.rules[0].keep"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := valid
			tt.mutate(&r)
			cfg := EnricherConfig{Redaction: r}
			errs := cfg.Validate()
			if tt.wantErr == "" {
				assert.Empty(t, errs)
				return
			}
			assert.ErrorContains(t, errs, tt.wantErr)
		})
	}
}
