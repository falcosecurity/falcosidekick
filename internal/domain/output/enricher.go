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
	"fmt"
	"regexp"

	"github.com/falcosecurity/falcosidekick/internal/utils"
)

const truncateFieldSuffixLen = 5 // len("[...]")

// EnricherConfig holds event enrichment settings.
type EnricherConfig struct {
	CustomFields           map[string]string `json:"custom_fields" mapstructure:"custom_fields"`
	TemplatedFields        map[string]string `json:"templated_fields" mapstructure:"templated_fields"`
	BracketReplacer        string            `json:"bracket_replacer" mapstructure:"bracket_replacer"`
	CustomTags             []string          `json:"custom_tags" mapstructure:"custom_tags"`
	Redaction              RedactionConfig   `json:"redaction" mapstructure:"redaction"`
	TruncateEventThreshold int               `json:"truncate_event_threshold" mapstructure:"truncate_event_threshold"`
	TruncateFieldThreshold int               `json:"truncate_field_threshold" mapstructure:"truncate_field_threshold"`
}

// RedactionConfig masks secrets in the output and the string output fields of every event.
type RedactionConfig struct {
	Mask  string          `json:"mask" mapstructure:"mask"`
	Rules []RedactionRule `json:"rules" mapstructure:"rules"`
	// BuiltinRules uses the secret patterns of github.com/docker/portcullis: cloud keys, tokens,
	// connection-string passwords and so on.
	BuiltinRules bool `json:"builtin_rules" mapstructure:"builtin_rules"`
	Enabled      bool `json:"enabled" mapstructure:"enabled"`
}

// RedactionRule is a user-defined pattern. When the pattern has a capture group, only the first
// group is masked; otherwise the whole match is.
type RedactionRule struct {
	Name    string `json:"name" mapstructure:"name"`
	Pattern string `json:"pattern" mapstructure:"pattern"`
	// Keep leaves the first Keep characters of the secret in place, to tell secrets apart.
	Keep int `json:"keep" mapstructure:"keep"`
}

// Validate checks enricher settings for errors.
func (c *EnricherConfig) Validate() utils.ValidationErrors {
	var errs utils.ValidationErrors
	if c.TruncateEventThreshold < 0 {
		errs.Add("truncate_event_threshold", "must be >= 0")
	}
	if c.TruncateFieldThreshold < 0 {
		errs.Add("truncate_field_threshold", "must be >= 0")
	}
	if c.TruncateEventThreshold > 0 && c.TruncateFieldThreshold <= truncateFieldSuffixLen {
		errs.Add("truncate_field_threshold", fmt.Sprintf("must be > %d when event truncation is enabled", truncateFieldSuffixLen))
	}
	c.Redaction.validate(&errs)
	if len(errs) > 0 {
		return errs
	}
	return nil
}

func (c *RedactionConfig) validate(errs *utils.ValidationErrors) {
	if !c.Enabled {
		return
	}
	if c.Mask == "" {
		errs.Add("redaction.mask", "must not be empty")
	}
	if !c.BuiltinRules && len(c.Rules) == 0 {
		errs.Add("redaction", "builtin_rules is false and no rules are set, so nothing would be redacted")
	}
	for i, r := range c.Rules {
		key := fmt.Sprintf("redaction.rules[%d]", i)
		if r.Name == "" {
			errs.Add(key+".name", "must not be empty")
		}
		if r.Keep < 0 {
			errs.Add(key+".keep", "must be >= 0")
		}
		if r.Pattern == "" {
			errs.Add(key+".pattern", "must not be empty")
		} else if _, err := regexp.Compile(r.Pattern); err != nil {
			errs.Add(key+".pattern", "is not a valid regular expression")
		}
	}
}
