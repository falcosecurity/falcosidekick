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
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/falcosecurity/falcosidekick/internal/domain/output"
)

func TestBatchingConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     output.BatchingConfig
		wantErr bool
	}{
		{"disabled skips validation", output.BatchingConfig{Enabled: false}, false},
		{"valid enabled", output.BatchingConfig{Enabled: true, BatchSize: 100, FlushInterval: time.Second}, false},
		{"zero batch size", output.BatchingConfig{Enabled: true, BatchSize: 0, FlushInterval: time.Second}, true},
		{"negative batch size", output.BatchingConfig{Enabled: true, BatchSize: -1, FlushInterval: time.Second}, true},
		{"zero flush interval", output.BatchingConfig{Enabled: true, BatchSize: 100, FlushInterval: 0}, true},
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
