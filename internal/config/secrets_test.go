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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

func writeSecret(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func TestResolveSecrets(t *testing.T) {
	schema := output.Schema{
		Fields: []output.SchemaField{
			{Name: "password", Secret: true},
			{Name: "host", Secret: false},
		},
	}

	tests := []struct {
		cfg     map[string]any
		want    map[string]any
		name    string
		wantErr bool
	}{
		{
			name: "resolve from file",
			cfg: map[string]any{
				"password_file": writeSecret(t, "my-secret"),
			},
			want: map[string]any{
				"password": "my-secret",
			},
		},
		{
			name: "trailing newline stripped",
			cfg: map[string]any{
				"password_file": writeSecret(t, "my-secret\n"),
			},
			want: map[string]any{
				"password": "my-secret",
			},
		},
		{
			name: "trailing crlf stripped",
			cfg: map[string]any{
				"password_file": writeSecret(t, "my-secret\r\n"),
			},
			want: map[string]any{
				"password": "my-secret",
			},
		},
		{
			name: "direct value takes precedence",
			cfg: map[string]any{
				"password":      "inline-value",
				"password_file": writeSecret(t, "file-value"),
			},
			want: map[string]any{
				"password": "inline-value",
			},
		},
		{
			name: "non-secret field _file ignored",
			cfg: map[string]any{
				"url_file": "/some/path",
			},
			want: map[string]any{
				"url_file": "/some/path",
			},
		},
		{
			name: "missing file returns error",
			cfg: map[string]any{
				"password_file": "/nonexistent/secret",
			},
			wantErr: true,
		},
		{
			name: "empty file path ignored",
			cfg: map[string]any{
				"password_file": "",
			},
			want: map[string]any{
				"password_file": "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ResolveSecrets("test", tt.cfg, schema)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, tt.cfg)
		})
	}
}

func TestResolveSecretsErrorsNameTheFieldOnly(t *testing.T) {
	const sentinel = "s3cret-sentinel"
	schema := output.Schema{Fields: []output.SchemaField{{Name: "auth.password", Secret: true}}}
	dir := t.TempDir()
	for _, tc := range []struct {
		name, path, want string
	}{
		{name: "missing", path: filepath.Join(dir, sentinel, "password"), want: `output "kafka": auth.password_file: file does not exist`},
		{name: "directory", path: dir, want: `output "kafka": auth.password_file: cannot read file`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := map[string]any{"auth": map[string]any{"password_file": tc.path}}
			err := ResolveSecrets("kafka", cfg, schema)
			require.EqualError(t, err, tc.want)
			assert.NotContains(t, err.Error(), dir)
		})
	}
}

func TestResolveSecretsTargetEndpointFile(t *testing.T) {
	schema := output.Schema{Fields: []output.SchemaField{{Name: "secret_endpoint", Secret: true}}}
	cfg := map[string]any{"secret_endpoint_file": writeSecret(t, "/services/T/B/X\n")}
	require.NoError(t, ResolveSecrets("slack", cfg, schema))
	assert.Equal(t, map[string]any{"secret_endpoint": "/services/T/B/X"}, cfg)
}

func TestResolveSecretsNestedField(t *testing.T) {
	schema := output.Schema{
		Fields: []output.SchemaField{
			{Name: "auth.password", Secret: true},
		},
	}

	secretFile := writeSecret(t, "kafka-secret\n")
	cfg := map[string]any{
		"auth": map[string]any{
			"mechanism":     "plain",
			"username":      "falco",
			"password_file": secretFile,
		},
	}

	require.NoError(t, ResolveSecrets("kafka", cfg, schema))

	auth, ok := cfg["auth"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "kafka-secret", auth["password"])
	assert.Equal(t, "plain", auth["mechanism"])
	assert.Equal(t, "falco", auth["username"])
	_, hasFileKey := auth["password_file"]
	assert.False(t, hasFileKey, "_file key must be removed after resolution")
}

func TestResolveSecretsEmptySchema(t *testing.T) {
	cfg := map[string]any{"password_file": "/some/path"}
	require.NoError(t, ResolveSecrets("test", cfg, output.Schema{}))
	assert.Equal(t, "/some/path", cfg["password_file"], "no schema fields means no resolution")
}

func TestNavigateMap(t *testing.T) {
	tests := []struct {
		m          map[string]any
		name       string
		path       string
		wantLeaf   string
		wantParent bool
	}{
		{
			name:       "flat field",
			m:          map[string]any{"password": "secret"},
			path:       "password",
			wantParent: true,
			wantLeaf:   "password",
		},
		{
			name:       "nested field",
			m:          map[string]any{"auth": map[string]any{"password": "secret"}},
			path:       "auth.password",
			wantParent: true,
			wantLeaf:   "password",
		},
		{
			name:       "missing intermediate",
			m:          map[string]any{},
			path:       "auth.password",
			wantParent: false,
		},
		{
			name:       "intermediate not a map",
			m:          map[string]any{"auth": "not-a-map"},
			path:       "auth.password",
			wantParent: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parent, leaf := utils.NavigateMap(tt.m, tt.path)
			if tt.wantParent {
				assert.NotNil(t, parent)
				assert.Equal(t, tt.wantLeaf, leaf)
			} else {
				assert.Nil(t, parent)
			}
		})
	}
}
