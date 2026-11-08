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

package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/catalog"
	"github.com/falcosecurity/falcosidekick/internal/domain/core"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/all"
	"github.com/falcosecurity/falcosidekick/internal/outputs/webhook"
)

func TestUIConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     core.UIConfig
		wantErr bool
	}{
		{"disabled", core.UIConfig{Enabled: false}, false},
		{"enabled with backend", core.UIConfig{Enabled: true, EventSource: "memory"}, false},
		{"enabled no backend", core.UIConfig{Enabled: true, EventSource: ""}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := tt.cfg.Validate()
			if tt.wantErr {
				assert.NotEmpty(t, errs)
			} else {
				assert.Empty(t, errs)
			}
		})
	}
}

func TestCheckEventSource(t *testing.T) {
	cat, err := catalog.New(all.Types())
	require.NoError(t, err)

	tests := []struct {
		name    string
		wantErr string
		ui      core.UIConfig
	}{
		{"inmemory accepted", "", core.UIConfig{Enabled: true, EventSource: "inmemory"}},
		{
			"webhook refused",
			`ui.event_source: output type "webhook" cannot serve events to the UI; use one of: inmemory`,
			core.UIConfig{Enabled: true, EventSource: "webhook"},
		},
		{"unknown name left to startup", "", core.UIConfig{Enabled: true, EventSource: "nonexistent"}},
		{"UI disabled not checked", "", core.UIConfig{Enabled: false, EventSource: "webhook"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckEventSource(&tt.ui, cat)
			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			assert.EqualError(t, err, tt.wantErr)
		})
	}
}

func TestCheckEventSourceWithoutAnyEventSourceType(t *testing.T) {
	cat, err := catalog.New([]output.Type{{Name: "webhook", New: webhook.OutputType.New}})
	require.NoError(t, err)

	err = CheckEventSource(&core.UIConfig{Enabled: true, EventSource: "webhook"}, cat)
	assert.EqualError(t, err, `ui.event_source: output type "webhook" cannot serve events to the UI`)
}
