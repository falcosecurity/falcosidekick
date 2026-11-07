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

package database

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain/core"
)

func TestPostgresSettings(t *testing.T) {
	passwordFile := filepath.Join(t.TempDir(), "pg")
	require.NoError(t, os.WriteFile(passwordFile, []byte("from-file\n"), 0o600))
	cfg := &core.PostgresConfig{
		Host: "db.example", Port: 6543, Database: `it's "odd"`, User: `back\slash`,
		PasswordFile: passwordFile, SSLMode: core.PostgresSSLDisable, MaxConnections: 1, PollInterval: time.Second,
	}

	settings, err := PostgresSettings(cfg)
	require.NoError(t, err)
	assert.Equal(t, "db.example", settings.Host)
	assert.Equal(t, uint16(6543), settings.Port)
	assert.Equal(t, `it's "odd"`, settings.Database)
	assert.Equal(t, `back\slash`, settings.User)
	assert.Equal(t, "from-file", settings.Password)
	assert.Nil(t, settings.TLSConfig, "sslmode disable")
	assert.Equal(t, "falcosidekick", settings.RuntimeParams["application_name"])

	cfg.PasswordFile, cfg.Password = "", "inline"
	settings, err = PostgresSettings(cfg)
	require.NoError(t, err)
	assert.Equal(t, "inline", settings.Password)

	cfg.SSLMode = core.PostgresSSLVerifyFull
	settings, err = PostgresSettings(cfg)
	require.NoError(t, err)
	require.NotNil(t, settings.TLSConfig)
	assert.Equal(t, "db.example", settings.TLSConfig.ServerName)
	assert.False(t, settings.TLSConfig.InsecureSkipVerify)

	cfg.Password, cfg.PasswordFile = "", filepath.Join(t.TempDir(), "missing")
	_, err = PostgresSettings(cfg)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), cfg.PasswordFile, "the path is not repeated")
}
