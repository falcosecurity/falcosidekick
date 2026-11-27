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

package pipeline

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/docker/portcullis"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
)

// redactor masks secrets in an event before it reaches any output.
type redactor struct {
	mask    string
	rules   []redactionRule
	builtin bool
}

type redactionRule struct {
	re   *regexp.Regexp
	keep int
}

// newRedactor returns nil when redaction is disabled.
func newRedactor(cfg output.RedactionConfig) (*redactor, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	r := &redactor{mask: cfg.Mask, builtin: cfg.BuiltinRules}
	for _, rule := range cfg.Rules {
		re, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return nil, fmt.Errorf("enricher: redaction rule %q: invalid pattern", rule.Name)
		}
		r.rules = append(r.rules, redactionRule{re: re, keep: rule.Keep})
	}
	return r, nil
}

func (r *redactor) redactEvent(evt *event.Event) {
	evt.Output = r.redact(evt.Output)
	for k, v := range evt.OutputFields {
		if s, ok := v.(string); ok {
			evt.OutputFields[k] = r.redact(s)
		}
	}
}

// redact applies the user rules first, then the built-in ones.
func (r *redactor) redact(s string) string {
	if s == "" {
		return s
	}
	for _, rule := range r.rules {
		s = rule.apply(s, r.mask)
	}
	if r.builtin {
		s = r.redactBuiltin(s)
	}
	return s
}

func (r *redactor) redactBuiltin(s string) string {
	matches := portcullis.Find(s)
	if len(matches) == 0 {
		return s
	}
	var b strings.Builder
	cursor := 0
	for _, m := range matches {
		_, _ = b.WriteString(s[cursor:m.Start])
		_, _ = b.WriteString(r.mask)
		cursor = m.End
	}
	_, _ = b.WriteString(s[cursor:])
	return b.String()
}

// apply masks the first capture group of every match, or the whole match when the pattern has no group.
func (rule redactionRule) apply(s, mask string) string {
	idx := rule.re.FindAllStringSubmatchIndex(s, -1)
	if len(idx) == 0 {
		return s
	}
	var b strings.Builder
	cursor := 0
	for _, m := range idx {
		start, end := m[0], m[1]
		if len(m) >= 4 && m[2] >= 0 {
			start, end = m[2], m[3]
		}
		if start < cursor {
			continue
		}
		start += keepPrefixLen(s[start:end], rule.keep)
		_, _ = b.WriteString(s[cursor:start])
		_, _ = b.WriteString(mask)
		cursor = end
	}
	_, _ = b.WriteString(s[cursor:])
	return b.String()
}

// keepPrefixLen returns the byte length of the first keep characters of secret.
// It keeps nothing when the secret is not longer than keep, so a short secret is never shown whole.
func keepPrefixLen(secret string, keep int) int {
	if keep <= 0 {
		return 0
	}
	n := 0
	for i := range secret {
		if n == keep {
			return i
		}
		n++
	}
	return 0
}
