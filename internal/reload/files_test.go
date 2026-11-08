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

package reload

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain/output"
)

func TestFileFieldsDigest(t *testing.T) {
	fields := []output.SchemaField{
		{Name: "token", Type: "string", Secret: true},
		{Name: "tls.ca_file", Type: "string", File: true},
		{Name: "certs", Type: "list", File: true},
		{Name: "headers", Type: "map", EntryFields: []output.SchemaField{
			{Name: "files", Type: "list", File: true},
		}},
	}
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	writeFile(t, ca, "ca")
	other := filepath.Join(dir, "other.pem")
	writeFile(t, other, "other")
	with := func(cfg map[string]any) string {
		t.Helper()
		digest, err := fileFieldsDigest("webhook", cfg, fields)
		require.NoError(t, err)
		return digest
	}
	withCA := map[string]any{"tls": map[string]any{"ca_file": ca}}

	t.Run("no File field set", func(t *testing.T) {
		assert.Empty(t, with(map[string]any{
			"token_file": ca,
			"headers":    map[string]any{"X-A": map[string]any{"files": []any{ca}}},
		}), "secret files and entry files are not File fields")
	})
	t.Run("same contents, same digest", func(t *testing.T) {
		first := with(withCA)
		require.NotEmpty(t, first)
		assert.Equal(t, first, with(withCA))
	})
	t.Run("contents change the digest", func(t *testing.T) {
		before := with(withCA)
		writeFile(t, ca, "renewed")
		assert.NotEqual(t, before, with(withCA))
	})
	t.Run("the location is part of the digest", func(t *testing.T) {
		assert.NotEqual(t, with(map[string]any{"certs": []any{ca, other}}), with(map[string]any{"certs": []any{other, ca}}))
	})
	t.Run("missing file", func(t *testing.T) {
		missing := filepath.Join(dir, "missing")
		_, err := fileFieldsDigest("webhook", map[string]any{"tls": map[string]any{"ca_file": missing}}, fields)
		require.EqualError(t, err, `output "webhook": tls.ca_file: file does not exist`)
		assert.NotContains(t, err.Error(), dir)
	})
	t.Run("not a path", func(t *testing.T) {
		_, err := fileFieldsDigest("webhook", map[string]any{"certs": 3}, fields)
		require.EqualError(t, err, `output "webhook": certs: must be a file path`)
	})
}

// kubeletMount lays out dir as kubelet mounts a Secret: dir/<key> -> ..data/<key>, ..data -> version.
func kubeletMount(t *testing.T, dir, version string, keys map[string]string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, version), 0o700))
	for key, value := range keys {
		writeFile(t, filepath.Join(dir, version, key), value)
		link := filepath.Join(dir, key)
		if _, err := os.Lstat(link); os.IsNotExist(err) {
			require.NoError(t, os.Symlink(filepath.Join("..data", key), link))
		}
	}
	data := filepath.Join(dir, "..data")
	if _, err := os.Lstat(data); os.IsNotExist(err) {
		require.NoError(t, os.Symlink(version, data))
		return
	}
	// The kubelet swap: a new link renamed over ..data.
	require.NoError(t, os.Symlink(version, filepath.Join(dir, "..data_tmp")))
	require.NoError(t, os.Rename(filepath.Join(dir, "..data_tmp"), data))
}

func TestSecretPaths(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "plain"), "p")
	kubeletMount(t, filepath.Join(root, "webhook"), "..2026_11_08_v1", map[string]string{"token": "t"})
	require.NoError(t, os.Mkdir(filepath.Join(root, "..2026_11_08_hidden"), 0o700))
	require.NoError(t, os.Mkdir(filepath.Join(root, "empty"), 0o700))
	linked := t.TempDir()
	writeFile(t, filepath.Join(linked, "key"), "k")
	require.NoError(t, os.Symlink(linked, filepath.Join(root, "linked")))
	require.NoError(t, os.Mkdir(filepath.Join(root, "empty", "deeper"), 0o700))

	other := t.TempDir()
	referenced := filepath.Join(other, "ca.pem")
	missingRoot := filepath.Join(t.TempDir(), "missing")

	tests := []struct {
		referenced func() []string
		name       string
		roots      []string
		wantDirs   []string
		wantFiles  []string
	}{
		{name: "nothing"},
		{
			name:  "roots and the directories below them",
			roots: []string{root + string(filepath.Separator)},
			wantDirs: []string{root, filepath.Join(root, "empty"), filepath.Join(root, "linked"),
				filepath.Join(root, "webhook")},
			wantFiles: []string{filepath.Join(root, "linked", "key"), filepath.Join(root, "plain"),
				filepath.Join(root, "webhook", "token")},
		},
		{
			name:       "referenced files outside the roots",
			referenced: func() []string { return []string{referenced, referenced, filepath.Join(other, ".", "x")} },
			wantDirs:   []string{other},
			wantFiles:  []string{referenced, filepath.Join(other, "x")},
		},
		{
			name:     "a missing root is still listed",
			roots:    []string{missingRoot},
			wantDirs: []string{missingRoot},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewSecretPaths(tt.roots, tt.referenced)
			assert.Equal(t, tt.wantDirs, nilIfEmpty(s.Dirs()))
			assert.Equal(t, tt.wantFiles, nilIfEmpty(s.Files()))
		})
	}
}

func nilIfEmpty(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return s
}
