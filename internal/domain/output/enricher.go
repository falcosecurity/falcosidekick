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

	"github.com/falcosecurity/falcosidekick/internal/utils"
)

const truncateFieldSuffixLen = 5 // len("[...]")

// EnricherConfig holds event enrichment settings.
type EnricherConfig struct {
	CustomFields           map[string]string `json:"customfields" mapstructure:"customfields"`
	TemplatedFields        map[string]string `json:"templatedfields" mapstructure:"templatedfields"`
	BracketReplacer        string            `json:"bracketreplacer" mapstructure:"bracketreplacer"`
	CustomTags             []string          `json:"customtags" mapstructure:"customtags"`
	TruncateEventThreshold int               `json:"truncate_event_threshold" mapstructure:"truncate_event_threshold"`
	TruncateFieldThreshold int               `json:"truncate_field_threshold" mapstructure:"truncate_field_threshold"`
}

// Validate checks enricher settings for errors.
func (c *EnricherConfig) Validate() utils.ValidationErrors {
	var errs utils.ValidationErrors
	if c.TruncateEventThreshold < 0 {
		errs.Add("truncate_event_threshold", fmt.Sprintf("must be >= 0, got %d", c.TruncateEventThreshold))
	}
	if c.TruncateFieldThreshold < 0 {
		errs.Add("truncate_field_threshold", fmt.Sprintf("must be >= 0, got %d", c.TruncateFieldThreshold))
	}
	if c.TruncateEventThreshold > 0 && c.TruncateFieldThreshold <= truncateFieldSuffixLen {
		errs.Add("truncate_field_threshold", fmt.Sprintf("must be > %d when event truncation is enabled, got %d", truncateFieldSuffixLen, c.TruncateFieldThreshold))
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}
