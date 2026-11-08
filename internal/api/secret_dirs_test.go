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

package api

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/database"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

const secretContent = "secret-content-never-listed"

func writeSecretFile(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
}

// mountKubernetesSecret lays out dir/name the way the kubelet mounts a Secret volume: the keys are
// symlinks through ..data to a timestamped directory.
func mountKubernetesSecret(t *testing.T, dir, name string, keys ...string) {
	t.Helper()
	mount := filepath.Join(dir, name)
	stamp := filepath.Join(mount, "..2026_11_08_22_00_00.123456789")
	for _, key := range keys {
		writeSecretFile(t, filepath.Join(stamp, key), secretContent)
	}
	require.NoError(t, os.Symlink(filepath.Base(stamp), filepath.Join(mount, "..data")))
	for _, key := range keys {
		require.NoError(t, os.Symlink(filepath.Join("..data", key), filepath.Join(mount, key)))
	}
}

func TestListSecretDirs(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	writeSecretFile(t, filepath.Join(outside, "stranger"), secretContent)

	mountKubernetesSecret(t, root, "slack", "webhook_url")
	mountKubernetesSecret(t, root, "postgres-tls", "tls.crt", "ca.crt")
	writeSecretFile(t, filepath.Join(root, "token"), secretContent)
	writeSecretFile(t, filepath.Join(root, ".hidden"), secretContent)
	writeSecretFile(t, filepath.Join(root, "large"), strings.Repeat("a", utils.MaxFileSize+1))
	writeSecretFile(t, filepath.Join(root, "plain", "key"), secretContent)
	writeSecretFile(t, filepath.Join(root, "plain", "nested", "deep"), secretContent)
	require.NoError(t, os.MkdirAll(filepath.Join(root, "empty"), 0o700))
	require.NoError(t, os.Symlink(filepath.Join(outside, "stranger"), filepath.Join(root, "escape")))
	require.NoError(t, os.Symlink(outside, filepath.Join(root, "escaped-dir")))
	require.NoError(t, syscall.Mkfifo(filepath.Join(root, "fifo"), 0o600))
	missing := filepath.Join(root, "missing")

	got := listSecretDirs([]string{root, missing}, maxListedSecretFiles)

	assert.False(t, got.Truncated)
	require.Len(t, got.Dirs, 2)
	assert.Equal(t, secretDirListing{
		Path: root,
		Keys: []string{"token"},
		Secrets: []secretListing{
			{Name: "plain", Path: filepath.Join(root, "plain"), Keys: []string{"key"}},
			{Name: "postgres-tls", Path: filepath.Join(root, "postgres-tls"), Keys: []string{"ca.crt", "tls.crt"}},
			{Name: "slack", Path: filepath.Join(root, "slack"), Keys: []string{"webhook_url"}},
		},
	}, got.Dirs[0], "hidden entries, ..data, oversized files, fifos, nested and empty directories and links out are left out")
	assert.Equal(t, secretDirListing{Path: missing, Keys: []string{}, Secrets: []secretListing{}}, got.Dirs[1])

	// Every listed file is one a PUT accepts, so the picker offers nothing the API refuses.
	for _, dir := range got.Dirs {
		for _, key := range dir.Keys {
			assert.NoError(t, allowedFile(filepath.Join(dir.Path, key), []string{root}), key)
		}
		for _, secret := range dir.Secrets {
			for _, key := range secret.Keys {
				assert.NoError(t, allowedFile(filepath.Join(secret.Path, key), []string{root}), secret.Name+"/"+key)
			}
		}
	}
}

func TestListSecretDirsIsBounded(t *testing.T) {
	root := t.TempDir()
	writeSecretFile(t, filepath.Join(root, "a"), secretContent)
	writeSecretFile(t, filepath.Join(root, "b"), secretContent)
	mountKubernetesSecret(t, root, "one", "x", "y")
	mountKubernetesSecret(t, root, "two", "z")

	for _, tc := range []struct {
		name      string
		keys      []string
		secrets   []secretListing
		limit     int
		truncated bool
	}{
		{name: "all fit", limit: 5, keys: []string{"a", "b"}, secrets: []secretListing{
			{Name: "one", Path: filepath.Join(root, "one"), Keys: []string{"x", "y"}},
			{Name: "two", Path: filepath.Join(root, "two"), Keys: []string{"z"}},
		}},
		{name: "cut inside a secret", limit: 3, keys: []string{"a", "b"}, truncated: true, secrets: []secretListing{
			{Name: "one", Path: filepath.Join(root, "one"), Keys: []string{"x"}},
		}},
		{name: "cut in the directory", limit: 1, keys: []string{"a"}, truncated: true, secrets: []secretListing{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := listSecretDirs([]string{root}, tc.limit)
			assert.Equal(t, tc.truncated, got.Truncated)
			require.Len(t, got.Dirs, 1)
			assert.Equal(t, tc.keys, got.Dirs[0].Keys)
			assert.Equal(t, tc.secrets, got.Dirs[0].Secrets)
		})
	}
}

func TestGETSecretsListsNamesOnly(t *testing.T) {
	root := t.TempDir()
	mountKubernetesSecret(t, root, "slack", "webhook_url")

	for _, tc := range []struct {
		name       string
		want       string
		secretDirs []string
	}{
		{name: "no secret_dirs", want: `{"dirs":[],"truncated":false}`},
		{
			name:       "kubernetes mount",
			secretDirs: []string{root},
			want: `{"dirs":[{"path":` + quote(t, root) + `,"keys":[],"secrets":[{"name":"slack","path":` +
				quote(t, filepath.Join(root, "slack")) + `,"keys":["webhook_url"]}]}],"truncated":false}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rig := buildMutationRig(t, database.NewMemory(), newMutationTestCatalog(t), true)
			rig.Server.secretDirs = tc.secretDirs
			raw := requestSecretContract(t, rig.Server, http.MethodGet, "/api/v1/secrets", "", http.StatusOK)
			assert.JSONEq(t, tc.want, string(raw))
			assert.NotContains(t, string(raw), secretContent)
		})
	}
}

func quote(t *testing.T, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	require.NoError(t, err)
	return string(b)
}
