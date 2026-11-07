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
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain/core"
)

// The defaults select inmemory and give a postgres backend safe settings.
func TestLoadDatabaseDefaults(t *testing.T) {
	cfg, err := Load("")
	require.NoError(t, err)
	assert.Equal(t, core.DatabaseInMemory, cfg.Database.Backend)
	assert.Equal(t, 30*time.Second, cfg.Database.ConnectTimeout)
	assert.Equal(t, core.PostgresConfig{Port: 5432, SSLMode: core.PostgresSSLVerifyFull, MaxConnections: 4, PollInterval: 10 * time.Second},
		cfg.Database.Postgres)
}
