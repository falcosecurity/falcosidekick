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

	"github.com/falcosecurity/falcosidekick/internal/domain/core"
)

func TestDatabaseConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		backend core.DatabaseBackend
		wantErr bool
	}{
		{"memory", core.DatabaseInMemory, false},
		{"sqlite", core.DatabaseSQLite, false},
		{"postgres", core.DatabasePostgres, false},
		{"invalid", core.DatabaseBackend("redis"), true},
		{"empty", core.DatabaseBackend(""), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := core.DatabaseConfig{Backend: tt.backend}
			errs := cfg.Validate()
			if tt.wantErr {
				assert.NotEmpty(t, errs)
			} else {
				assert.Empty(t, errs)
			}
		})
	}
}
