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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain/output"
)

func TestNewRedactorDisabled(t *testing.T) {
	r, err := newRedactor(output.RedactionConfig{Enabled: false, BuiltinRules: true, Mask: "[REDACTED]"})
	require.NoError(t, err)
	assert.Nil(t, r)
}

func TestNewRedactorInvalidPattern(t *testing.T) {
	_, err := newRedactor(output.RedactionConfig{
		Enabled: true,
		Mask:    "[REDACTED]",
		Rules:   []output.RedactionRule{{Name: "bad", Pattern: "(unclosed"}},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bad")
	assert.NotContains(t, err.Error(), "(unclosed", "the pattern is not echoed")
}

func TestRedactorRules(t *testing.T) {
	tests := []struct {
		name  string
		mask  string
		input string
		want  string
		rule  output.RedactionRule
	}{
		{
			name:  "capture group is masked",
			rule:  output.RedactionRule{Name: "pg", Pattern: `postgresql://[^:/]+:([^@]+)@`},
			mask:  "*****",
			input: "psql postgresql://appuser:EAzndiaZ@db.internal:5432/appdb",
			want:  "psql postgresql://appuser:*****@db.internal:5432/appdb",
		},
		{
			name:  "keep leaves a prefix",
			rule:  output.RedactionRule{Name: "pg", Pattern: `postgresql://[^:/]+:([^@]+)@`, Keep: 2},
			mask:  "*****",
			input: "psql postgresql://appuser:EAzndiaZ@db.internal:5432/appdb",
			want:  "psql postgresql://appuser:EA*****@db.internal:5432/appdb",
		},
		{
			name:  "keep never shows a short secret whole",
			rule:  output.RedactionRule{Name: "pw", Pattern: `--password=(\S+)`, Keep: 4},
			mask:  "*",
			input: "app --password=abcd",
			want:  "app --password=*",
		},
		{
			name:  "keep counts characters, not bytes",
			rule:  output.RedactionRule{Name: "pw", Pattern: `--password=(\S+)`, Keep: 2},
			mask:  "*",
			input: "app --password=éèsecret",
			want:  "app --password=éè*",
		},
		{
			name:  "whole match without a group",
			rule:  output.RedactionRule{Name: "tok", Pattern: `tok_[a-z0-9]+`},
			mask:  "[REDACTED]",
			input: "a tok_abc123 and tok_def456",
			want:  "a [REDACTED] and [REDACTED]",
		},
		{
			name:  "optional group that did not match masks the whole match",
			rule:  output.RedactionRule{Name: "opt", Pattern: `key(=(\w+))?`},
			mask:  "X",
			input: "key",
			want:  "X",
		},
		{
			name:  "no match leaves the text alone",
			rule:  output.RedactionRule{Name: "tok", Pattern: `tok_[a-z0-9]+`},
			mask:  "X",
			input: "nothing to see",
			want:  "nothing to see",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := newRedactor(output.RedactionConfig{Enabled: true, Mask: tt.mask, Rules: []output.RedactionRule{tt.rule}})
			require.NoError(t, err)
			assert.Equal(t, tt.want, r.redact(tt.input))
		})
	}
}

func TestRedactorBuiltinRules(t *testing.T) {
	r, err := newRedactor(output.RedactionConfig{Enabled: true, BuiltinRules: true, Mask: "***"})
	require.NoError(t, err)

	got := r.redact("aws s3 ls with AWS_ACCESS_KEY_ID=AKIARZPUZDIKQEXAMPLE set")
	assert.NotContains(t, got, "AKIARZPUZDIKQEXAMPLE")
	assert.Contains(t, got, "***")
	assert.Equal(t, "ls -la /tmp", r.redact("ls -la /tmp"))
	assert.Equal(t, got, r.redact(got), "redacting twice changes nothing")
}

func TestRedactorBuiltinRulesOff(t *testing.T) {
	r, err := newRedactor(output.RedactionConfig{
		Enabled: true,
		Mask:    "X",
		Rules:   []output.RedactionRule{{Name: "tok", Pattern: `tok_\w+`}},
	})
	require.NoError(t, err)
	in := "AWS_ACCESS_KEY_ID=AKIARZPUZDIKQEXAMPLE tok_abc"
	assert.Equal(t, "AWS_ACCESS_KEY_ID=AKIARZPUZDIKQEXAMPLE X", r.redact(in))
}

func TestEnricherRedactsOutputAndFields(t *testing.T) {
	cfg := testEnricherConfig()
	cfg.TemplatedFields = map[string]string{"copy": `{{ index . "proc.cmdline" }}`}
	cfg.Redaction = output.RedactionConfig{
		Enabled: true,
		Mask:    "*****",
		Rules:   []output.RedactionRule{{Name: "pg", Pattern: `postgresql://[^:/]+:([^@]+)@`}},
	}
	e, err := NewEnricher(cfg)
	require.NoError(t, err)

	evt := newTestEvent()
	evt.Output = "Database client run (cmdline=psql postgresql://app:EAzndiaZ@db:5432/appdb)"
	evt.OutputFields["proc.cmdline"] = "psql postgresql://app:EAzndiaZ@db:5432/appdb"
	evt.OutputFields["proc.pid"] = int64(42)
	e.Enrich(evt)

	assert.Equal(t, "Database client run (cmdline=psql postgresql://app:*****@db:5432/appdb)", evt.Output)
	assert.Equal(t, "psql postgresql://app:*****@db:5432/appdb", evt.OutputFields["proc.cmdline"])
	assert.Equal(t, "psql postgresql://app:*****@db:5432/appdb", evt.OutputFields["copy"], "a templated copy is redacted too")
	assert.Equal(t, int64(42), evt.OutputFields["proc.pid"])
	assert.Equal(t, "bash", evt.OutputFields["proc.name"])
}
