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

var fileFields = []output.SchemaField{
	{Name: "token", Type: "string", Secret: true},
	{Name: "password", Type: "map", Secret: true},
	{Name: "tls.ca_file", Type: "string", File: true},
	{Name: "certs", Type: "list", File: true},
	{Name: "headers", Type: "map", EntryFields: []output.SchemaField{
		{Name: "files", Type: "list", File: true},
	}},
}

func TestCollectFilePaths(t *testing.T) {
	tests := []struct {
		cfg     map[string]any
		want    map[string]string
		name    string
		wantErr string
	}{
		{name: "empty", cfg: map[string]any{}, want: map[string]string{}},
		{
			name: "secret file variant",
			cfg:  map[string]any{"token_file": "/s/token", "password_file": "/s/ignored"},
			want: map[string]string{"token_file": "/s/token"},
		},
		{
			name: "file field under a parent",
			cfg:  map[string]any{"tls": map[string]any{"ca_file": "/s/ca.pem"}},
			want: map[string]string{"tls.ca_file": "/s/ca.pem"},
		},
		{
			name: "empty path is no path",
			cfg:  map[string]any{"token_file": ""},
			want: map[string]string{},
		},
		{
			name: "list of any",
			cfg:  map[string]any{"certs": []any{"/s/a", "/s/b"}},
			want: map[string]string{"certs[0]": "/s/a", "certs[1]": "/s/b"},
		},
		{
			name: "list of strings",
			cfg:  map[string]any{"certs": []string{"/s/a"}},
			want: map[string]string{"certs[0]": "/s/a"},
		},
		{
			name: "map entries",
			cfg: map[string]any{"headers": map[string]any{
				"X-A": map[string]any{"files": []any{"/s/x"}},
				"X-B": "not an object",
			}},
			want: map[string]string{`headers["X-A"].files[0]`: "/s/x"},
		},
		{
			name:    "list item not a string",
			cfg:     map[string]any{"token_file": "/s/token", "certs": []any{"/s/a", 1}},
			want:    map[string]string{"token_file": "/s/token", "certs[0]": "/s/a"},
			wantErr: "certs[1]: must be a string",
		},
		{
			name:    "not a path",
			cfg:     map[string]any{"tls": map[string]any{"ca_file": map[string]any{"path": "x"}}},
			want:    map[string]string{},
			wantErr: "tls.ca_file: must be a file path",
		},
		{
			name:    "entry not a path",
			cfg:     map[string]any{"headers": map[string]any{"X-A": map[string]any{"files": 3}}},
			want:    map[string]string{},
			wantErr: `headers["X-A"].files: must be a file path`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			paths := make(map[string]string)
			err := CollectFilePaths(tt.cfg, fileFields, paths)
			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.want, paths, "paths keeps what was collected before an error")
		})
	}
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
