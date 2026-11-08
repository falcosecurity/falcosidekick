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

package event

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPriorityGTE(t *testing.T) {
	tests := []struct {
		name string
		a    Priority
		b    Priority
		want bool
	}{
		{"emergency >= debug", PriorityEmergency, PriorityDebug, true},
		{"critical >= warning", PriorityCritical, PriorityWarning, true},
		{"warning >= warning", PriorityWarning, PriorityWarning, true},
		{"debug >= emergency", PriorityDebug, PriorityEmergency, false},
		{"debug >= debug", PriorityDebug, PriorityDebug, true},
		{"informational >= notice", PriorityInformational, PriorityNotice, false},
		{"notice >= informational", PriorityNotice, PriorityInformational, true},
		{"alert >= critical", PriorityAlert, PriorityCritical, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.a.GTE(tt.b))
		})
	}
}

func TestParsePriority(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    Priority
		wantErr bool
	}{
		{"lowercase debug", "debug", PriorityDebug, false},
		{"uppercase Warning", "Warning", PriorityWarning, false},
		{"mixed case CRITICAL", "CRITICAL", PriorityCritical, false},
		{"empty string rejected", "", Priority(""), true},
		{"with spaces", "  error  ", PriorityError, false},
		{"informational", "informational", PriorityInformational, false},
		{"notice", "notice", PriorityNotice, false},
		{"alert", "alert", PriorityAlert, false},
		{"emergency", "emergency", PriorityEmergency, false},
		{"unknown value", "fatal", Priority(""), true},
		{"numeric string", "5", Priority(""), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePriority(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestPriorityString(t *testing.T) {
	tests := []struct {
		input Priority
		want  string
	}{
		{PriorityDebug, "Debug"},
		{PriorityWarning, "Warning"},
		{PriorityEmergency, "Emergency"},
		{PriorityInformational, "Informational"},
		{PriorityNotice, "Notice"},
		{Priority(""), ""},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.input.String())
		})
	}
}

func TestEventValidate(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name    string
		event   Event
		wantErr bool
	}{
		{
			name: "valid event",
			event: Event{
				Rule:         "Test rule",
				Time:         now,
				Priority:     PriorityWarning,
				Output:       "test output",
				OutputFields: map[string]interface{}{"key": "value"},
				Source:       "syscall",
			},
		},
		{
			name:    "missing rule",
			event:   Event{Time: now, Priority: PriorityWarning, Source: "syscall", OutputFields: map[string]interface{}{"k": "v"}},
			wantErr: true,
		},
		{
			name:    "missing time",
			event:   Event{Rule: "Test rule", Priority: PriorityWarning, Source: "syscall", OutputFields: map[string]interface{}{"k": "v"}},
			wantErr: true,
		},
		{
			name:    "nil output fields rejected",
			event:   Event{Rule: "Test rule", Time: now, Priority: PriorityWarning, Source: "syscall"},
			wantErr: true,
		},
		{
			name:    "empty output fields rejected",
			event:   Event{Rule: "Test rule", Time: now, Priority: PriorityWarning, Source: "syscall", OutputFields: map[string]interface{}{}},
			wantErr: true,
		},
		{
			name:    "invalid priority rejected",
			event:   Event{Rule: "Test rule", Time: now, Priority: "bogus", OutputFields: map[string]interface{}{"k": "v"}},
			wantErr: true,
		},
		{
			name:    "empty priority rejected",
			event:   Event{Rule: "Test rule", Time: now, Priority: "", OutputFields: map[string]interface{}{"k": "v"}},
			wantErr: true,
		},
		{
			name:  "empty source defaults to syscall",
			event: Event{Rule: "Test rule", Time: now, Priority: PriorityWarning, OutputFields: map[string]interface{}{"k": "v"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.event.Validate()
			if tt.wantErr {
				require.Error(t, err)
				assert.True(t, errors.Is(err, ErrInvalidEvent))
				return
			}
			require.NoError(t, err)
			assert.NotNil(t, tt.event.OutputFields)
			assert.NotEmpty(t, tt.event.Source)
		})
	}
}

func TestEventJSONRoundTrip(t *testing.T) {
	original := Event{
		UUID:     "test-uuid-123",
		Output:   "File below a known binary directory opened for writing",
		Priority: PriorityError,
		Rule:     "Write below binary dir",
		Time:     time.Date(2026, 4, 1, 10, 30, 0, 0, time.UTC),
		OutputFields: map[string]interface{}{
			"fd.name":      "/bin/hack",
			"proc.cmdline": "touch /bin/hack",
			"user.name":    "root",
		},
		Source:   "syscall",
		Tags:     []string{"filesystem", "mitre_persistence"},
		Hostname: "node-1",
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded Event
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.UUID, decoded.UUID)
	assert.Equal(t, original.Priority, decoded.Priority)
	assert.Equal(t, original.Rule, decoded.Rule)
	assert.True(t, original.Time.Equal(decoded.Time))
	assert.Equal(t, original.Source, decoded.Source)
	assert.Equal(t, original.Tags, decoded.Tags)
	assert.Equal(t, original.Hostname, decoded.Hostname)

	// Priority serialized as string in JSON
	assert.Contains(t, string(data), `"priority":"error"`)
}

func TestValidateNormalizesPriorityCase(t *testing.T) {
	cases := []struct {
		name  string
		input Priority
		want  Priority
	}{
		{"lowercase", Priority("warning"), PriorityWarning},
		{"title case from Falco HTTP output", Priority("Warning"), PriorityWarning},
		{"all caps", Priority("EMERGENCY"), PriorityEmergency},
		{"whitespace", Priority(" Warning "), PriorityWarning},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			evt := &Event{
				Time:         time.Now(),
				Rule:         "r",
				Priority:     tc.input,
				OutputFields: map[string]interface{}{"k": "v"},
			}
			if err := evt.Validate(); err != nil {
				t.Fatalf("Validate: %v", err)
			}
			if evt.Priority != tc.want {
				t.Fatalf("Priority not normalized: got %q want %q", evt.Priority, tc.want)
			}
		})
	}
}
