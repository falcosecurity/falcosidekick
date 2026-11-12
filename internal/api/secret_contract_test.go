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
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/catalog"
	"github.com/falcosecurity/falcosidekick/internal/database"
	"github.com/falcosecurity/falcosidekick/internal/domain/core"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/webhook"
)

func TestSecretContractGET(t *testing.T) {
	nested, ok := nestedMutationCatalog(t).Get("kafka")
	require.True(t, ok)
	cat, err := catalog.New([]output.Type{webhook.OutputType, nested})
	require.NoError(t, err)
	for _, tt := range []struct {
		name       string
		outputName string
		config     string
		public     string
		fields     map[string]bool
		hidden     []string
	}{
		{
			name:       "public headers and file paths survive",
			outputName: "webhook",
			config: `{"host":"https://example.invalid","endpoint":"/events","username":"reader","password":"scalar-private","bearer_token":"","headers":{
				"X-Team":{"values":["security"]},
				"X-Key~Id":{"values":["public-prefix"],"secrets":["header-private-one","header-private-two"],"files":["/run/secrets/header"]},
				"X-Empty":{"secrets":[]},"X-Null":{"secrets":null}}}`,
			public: `{"host":"https://example.invalid","endpoint":"/events","username":"reader","headers":{
				"X-Team":{"values":["security"]},"X-Key~Id":{"values":["public-prefix"],"files":["/run/secrets/header"]},
				"X-Empty":{},"X-Null":{}}}`,
			fields: map[string]bool{"/password": true, "/bearer_token": false, "/headers/X-Key~0Id/secrets": true,
				"/headers/X-Empty/secrets": false, "/headers/X-Null/secrets": false},
			hidden: []string{"scalar-private", "header-private-one", "header-private-two"},
		},
		{
			name:       "all case aliases are protected without renaming public keys",
			outputName: "webhook",
			config: `{"URL":"https://example.invalid/events","Password":"mixed-private","pa\u017f\u017fword":"unicode-private",
				"HEADERS":{"x-Custom":{"VaLuEs":["public-value"],"SeCrEtS":["mixed-header-private"],"secrets":["second-alias-private"]}}}`,
			public: `{"URL":"https://example.invalid/events","HEADERS":{"x-Custom":{"VaLuEs":["public-value"]}}}`,
			fields: map[string]bool{"/Password": true, "/pa\u017f\u017fword": true,
				"/HEADERS/x-Custom/SeCrEtS": true, "/HEADERS/x-Custom/secrets": true},
			hidden: []string{"mixed-private", "unicode-private", "mixed-header-private", "second-alias-private"},
		},
		{
			name:       "malformed header container is removed wholesale",
			outputName: "webhook",
			config:     `{"host":"https://example.invalid","endpoint":"/events","HEADERS":["container-private",{"token":"nested-container-private"}]}`,
			public:     `{"host":"https://example.invalid","endpoint":"/events"}`,
			fields:     map[string]bool{"/HEADERS": true},
			hidden:     []string{"container-private", "nested-container-private"},
		},
		{
			name:       "malformed header entries use escaped presence pointers",
			outputName: "webhook",
			config:     `{"headers":{"X-Key~/Id":["entry-private"],"X-Null":null,"X-Team":{"values":["security"]}}}`,
			public:     `{"headers":{"X-Team":{"values":["security"]}}}`,
			fields:     map[string]bool{"/headers/X-Key~0~1Id": true, "/headers/X-Null": false},
			hidden:     []string{"entry-private"},
		},
		{
			name:       "malformed nested secret parent is removed wholesale",
			outputName: "kafka",
			config:     `{"topic":"events","AUTH":["auth-container-private"]}`,
			public:     `{"topic":"events"}`,
			fields:     map[string]bool{"/AUTH": true},
			hidden:     []string{"auth-container-private"},
		},
		{
			name:       "unknown type protects every value including collections and numbers",
			outputName: "unregistered",
			config: `{"text":"unknown-private","nested/key~":{"password":"nested-private","number":918273645},
				"list":["array-private",{"token":"object-private"},918273646],"flag":true,"empty":"","null":null,"empty_list":[]}`,
			public: `{"nested/key~":{}}`,
			fields: map[string]bool{"/text": true, "/nested~1key~0/password": true, "/nested~1key~0/number": true,
				"/list": true, "/flag": true, "/empty": false, "/null": false, "/empty_list": false},
			hidden: []string{"unknown-private", "nested-private", "array-private", "object-private", "918273645", "918273646"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			db := database.NewMemory()
			require.NoError(t, db.Provision(t.Context(), &core.ProvisionRequest{
				Outputs: map[string]map[string]any{tt.outputName: parseSecretContractConfig(t, tt.config)},
			}))
			rig := buildMutationRig(t, db, cat, true)
			assertSecretContractReads(t, rig.Server, db, tt.outputName, tt.public, tt.fields, tt.hidden)
		})
	}
}

func TestSecretContractTypedMaps(t *testing.T) {
	cat, err := catalog.New([]output.Type{webhook.OutputType})
	require.NoError(t, err)
	for _, tt := range []struct {
		name   string
		config map[string]any
		public string
		fields map[string]bool
		hidden []string
	}{
		{
			name: "webhook",
			config: map[string]any{
				"headers": map[string]map[string][]string{
					"X-Typed": {"values": {"visible"}, "secrets": {"typed-private"}, "files": {"/run/secrets/typed"}},
				},
				"public": map[string]any{"large_integer": int64(9007199254740993), "nil_slice": []string(nil), "bytes": []byte("abc")},
			},
			public: `{"headers":{"X-Typed":{"values":["visible"],"files":["/run/secrets/typed"]}},
				"public":{"large_integer":9007199254740993,"nil_slice":null,"bytes":"YWJj"}}`,
			fields: map[string]bool{"/headers/X-Typed/secrets": true},
			hidden: []string{"typed-private"},
		},
		{
			name: "unregistered",
			config: map[string]any{
				"numbers": map[string]int64{"token": 918273647},
				"objects": []map[string]string{{"token": "typed-object-private"}},
				"array":   [2]string{"typed-array-private", "second-array-private"},
			},
			public: `{"numbers":{}}`,
			fields: map[string]bool{"/numbers/token": true, "/objects": true, "/array": true},
			hidden: []string{"918273647", "typed-object-private", "typed-array-private", "second-array-private"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			db := database.NewMemory()
			seedOutput(t, db, tt.name, tt.config)
			rig := buildMutationRig(t, db, cat, true)
			assertSecretContractReads(t, rig.Server, db, tt.name, tt.public, tt.fields, tt.hidden)
			stored, err := db.GetOutputConfig(t.Context(), tt.name)
			require.NoError(t, err)
			assert.Equal(t, tt.config, stored.Config)
		})
	}
}

func TestSecretContractPUT(t *testing.T) {
	cat, err := catalog.New([]output.Type{webhook.OutputType})
	require.NoError(t, err)
	headerFile := filepath.Join(t.TempDir(), "header")
	require.NoError(t, os.WriteFile(headerFile, []byte("file-private\n"), 0o600))
	for _, tt := range []struct {
		name     string
		patch    string
		secrets  string
		password any
		values   string
		legacy   bool
	}{
		{"omission retains credentials", `{}`, `["stored-one","stored-two"]`, "stored-password", `["visible"]`, false},
		{"omission retains literal legacy sentinel", `{}`, `["****"]`, "****", `["visible"]`, true},
		{"empty maps retain credentials", `{"headers":{"X-Key":{}}}`, `["stored-one","stored-two"]`, "stored-password", `["visible"]`, false},
		{"arrays replace", `{"headers":{"X-Key":{"secrets":["replacement-private"]}}}`, `["replacement-private"]`, "stored-password", `["visible"]`, false},
		{"empty arrays clear", `{"headers":{"X-Key":{"secrets":[]}}}`, `[]`, "stored-password", `["visible"]`, false},
		{"null removes", `{"headers":{"X-Key":{"secrets":null}},"password":null}`, `null`, nil, `["visible"]`, false},
		{"empty scalar clears", `{"password":""}`, `["stored-one","stored-two"]`, "", `["visible"]`, false},
		{"case aliases replace and preserve siblings", `{"HEADERS":{"X-Key":{"SeCrEtS":["replacement-private"],"VaLuEs":["new-public"]}},"PASSword":"replacement-password"}`, `["replacement-private"]`, "replacement-password", `["new-public"]`, false},
		{"public sentinel is literal", `{"headers":{"X-Key":{"values":["****"]}}}`, `["stored-one","stored-two"]`, "stored-password", `["****"]`, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := parseSecretContractConfig(t, `{"host":"https://example.invalid","endpoint":"/events","username":"reader","password":"stored-password",
				"headers":{"X-Key":{"values":["visible"],"secrets":["stored-one","stored-two"]},"X-Team":{"values":["security"]}}}`)
			cfg["headers"].(map[string]any)["X-Key"].(map[string]any)["files"] = []any{headerFile}
			if tt.legacy {
				cfg["password"] = "****"
				cfg["headers"].(map[string]any)["X-Key"].(map[string]any)["secrets"] = []any{"****"}
			}
			db := database.NewMemory()
			seedOutput(t, db, "webhook", cfg)
			rig := buildMutationRig(t, db, cat, true)
			body := `{"version":1,"config":` + tt.patch + `}`
			raw := requestSecretContract(t, rig.Server, http.MethodPut, "/api/v1/pipeline/outputs/webhook", body, http.StatusOK)

			want := parseSecretContractConfig(t, `{"host":"https://example.invalid","endpoint":"/events","username":"reader",
				"headers":{"X-Key":{"values":`+tt.values+`},"X-Team":{"values":["security"]}}}`)
			want["headers"].(map[string]any)["X-Key"].(map[string]any)["files"] = []any{headerFile}
			public, err := json.Marshal(want)
			require.NoError(t, err)
			// A null removes the key (RFC 7386), so the field is not reported at all.
			fields := map[string]bool{}
			if tt.password != nil {
				fields["/password"] = tt.password != ""
			}
			if tt.secrets != "null" {
				fields["/headers/X-Key/secrets"] = tt.secrets != "[]"
			}
			if len(fields) == 0 {
				fields = nil
			}
			hidden := []string{"stored-password", "stored-one", "stored-two", "replacement-private", "replacement-password", "file-private"}
			if tt.legacy {
				hidden = append(hidden, "****")
			}
			assertSecretContractResponse(t, raw, string(public), fields, hidden)

			var secrets any
			require.NoError(t, json.Unmarshal([]byte(tt.secrets), &secrets))
			if tt.password != nil {
				want["password"] = tt.password
			}
			if secrets != nil {
				want["headers"].(map[string]any)["X-Key"].(map[string]any)["secrets"] = secrets
			}
			stored, err := db.GetOutputConfig(t.Context(), "webhook")
			require.NoError(t, err)
			require.NotNil(t, stored)
			assert.Equal(t, want, stored.Config)
			assert.False(t, stored.Provisioned)
			assert.Len(t, rig.Server.pipeline.CollectOutputStatus(), 1)
			assertSecretContractReads(t, rig.Server, db, "webhook", string(public), fields, hidden)
		})
	}
}

func TestSecretContractPUTRejectsAmbiguousOrPlaceholderSecrets(t *testing.T) {
	cat, err := catalog.New([]output.Type{webhook.OutputType})
	require.NoError(t, err)
	for _, tt := range []struct {
		name      string
		patch     string
		reason    string
		ambiguous bool
	}{
		{"scalar", `{"password":"****"}`, "secret placeholder", false},
		{"scalar alias", `{"PASSword":"****"}`, "secret placeholder", false},
		{"unicode scalar alias", `{"pa\u017f\u017fword":"****"}`, "secret placeholder", false},
		{"array element", `{"headers":{"X-Key":{"secrets":["replacement-private","****"]}}}`, "secret placeholder", false},
		{"array aliases", `{"HEADERS":{"X-Key":{"SeCrEtS":["****"]}}}`, "secret placeholder", false},
		{"nested array object", `{"headers":{"X-Key":{"secrets":[{"token":"****"}]}}}`, "secret placeholder", false},
		{"duplicate scalar aliases", `{"password":"first-private","PASSWORD":"second-private"}`, "duplicate case-insensitive", false},
		{"duplicate container aliases", `{"headers":{},"HEADERS":{"X-Key":{"secrets":["replacement-private"]}}}`, "duplicate case-insensitive", false},
		{"duplicate entry aliases", `{"headers":{"X-Key":{"secrets":["first-private"],"SECRETS":["second-private"]}}}`, "duplicate case-insensitive", false},
		{"stored duplicate aliases", `{}`, "duplicate case-insensitive", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := parseSecretContractConfig(t, `{"host":"https://example.invalid","endpoint":"/events","password":"stored-private","headers":{"X-Key":{"secrets":["stored-header-private"]}}}`)
			if tt.ambiguous {
				cfg["PASSWORD"] = "stored-alias-private"
			}
			db := database.NewMemory()
			seedOutput(t, db, "webhook", cfg)
			before, err := db.GetOutputConfig(t.Context(), "webhook")
			require.NoError(t, err)
			rig := buildMutationRig(t, db, cat, true)
			raw := requestSecretContract(t, rig.Server, http.MethodPut, "/api/v1/pipeline/outputs/webhook", `{"version":1,"config":`+tt.patch+`}`, http.StatusBadRequest)
			assert.Contains(t, string(raw), tt.reason)
			for _, secret := range []string{"stored-private", "stored-header-private", "stored-alias-private", "replacement-private", "first-private", "second-private"} {
				assert.NotContains(t, string(raw), secret)
			}
			after, err := db.GetOutputConfig(t.Context(), "webhook")
			require.NoError(t, err)
			assert.Equal(t, before, after)
			assert.Empty(t, rig.Server.pipeline.CollectOutputStatus())
		})
	}
}

func TestSecretContractNestedScalarAliases(t *testing.T) {
	for _, tt := range []struct {
		name     string
		password any
		patch    string
		status   int
	}{
		{"omitted", "nested-private", `{"auth":{"USERNAME":"bob"}}`, http.StatusOK},
		{"replaced", "replacement-private", `{"auth":{"USERNAME":"bob","PASSWORD":"replacement-private"}}`, http.StatusOK},
		{"empty", "", `{"auth":{"USERNAME":"bob","PASSWORD":""}}`, http.StatusOK},
		{"null", nil, `{"auth":{"USERNAME":"bob","PASSWORD":null}}`, http.StatusOK},
		{"placeholder", "nested-private", `{"auth":{"PASSWORD":"****"}}`, http.StatusBadRequest},
		{"duplicate aliases", "nested-private", `{"auth":{"password":"first-private","PASSWORD":"second-private"}}`, http.StatusBadRequest},
	} {
		t.Run(tt.name, func(t *testing.T) {
			db := database.NewMemory()
			seedOutput(t, db, "kafka", map[string]any{
				"topic": "events", "AUTH": map[string]string{"SASL": "plain", "Username": "alice", "Password": "nested-private"},
			})
			rig := buildMutationRig(t, db, nestedMutationCatalog(t), true)
			assertSecretContractReads(t, rig.Server, db, "kafka", `{"topic":"events","AUTH":{"SASL":"plain","Username":"alice"}}`,
				map[string]bool{"/AUTH/Password": true}, []string{"nested-private"})
			before, err := db.GetOutputConfig(t.Context(), "kafka")
			require.NoError(t, err)
			raw := requestSecretContract(t, rig.Server, http.MethodPut, "/api/v1/pipeline/outputs/kafka", `{"version":1,"config":`+tt.patch+`}`, tt.status)
			stored, err := db.GetOutputConfig(t.Context(), "kafka")
			require.NoError(t, err)
			if tt.status != http.StatusOK {
				assert.Equal(t, before, stored)
				assert.Empty(t, rig.Server.pipeline.CollectOutputStatus())
				return
			}
			auth := map[string]any{"sasl": "plain", "username": "bob"}
			fields := map[string]bool(nil)
			if tt.password != nil { // a null removes the key
				auth["password"] = tt.password
				fields = map[string]bool{"/auth/password": tt.password != ""}
			}
			assert.Equal(t, map[string]any{"topic": "events", "auth": auth}, stored.Config)
			public := `{"topic":"events","auth":{"sasl":"plain","username":"bob"}}`
			hidden := []string{"nested-private", "replacement-private"}
			assertSecretContractResponse(t, raw, public, fields, hidden)
			assertSecretContractReads(t, rig.Server, db, "kafka", public, fields, hidden)
		})
	}
}

func parseSecretContractConfig(t *testing.T, raw string) map[string]any {
	t.Helper()
	var cfg map[string]any
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.UseNumber()
	require.NoError(t, decoder.Decode(&cfg))
	return cfg
}

func requestSecretContract(t *testing.T, srv *Server, method, path, body string, status int) []byte {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, status, resp.StatusCode, "%s %s: %s", method, path, raw)
	return raw
}

func assertSecretContractResponse(t *testing.T, raw []byte, public string, fields map[string]bool, hidden []string) outputConfigResponse {
	t.Helper()
	for _, secret := range hidden {
		assert.NotContains(t, string(raw), secret)
	}
	var got outputConfigResponse
	require.NoError(t, json.Unmarshal(raw, &got))
	require.NotNil(t, got.OutputConfigEntry)
	var envelope map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &envelope))
	assert.Equal(t, parseSecretContractConfig(t, public), parseSecretContractConfig(t, string(envelope["config"])))
	assert.Equal(t, fields, got.SecretFields)
	return got
}

func assertSecretContractReads(t *testing.T, srv *Server, db *database.Memory, name, public string, fields map[string]bool, hidden []string) {
	t.Helper()
	before, err := db.GetOutputConfig(t.Context(), name)
	require.NoError(t, err)
	require.NotNil(t, before)
	snapshot, err := json.Marshal(before)
	require.NoError(t, err)
	for _, path := range []string{"/api/v1/pipeline", "/api/v1/pipeline/outputs", "/api/v1/pipeline/outputs/" + name} {
		t.Run(path, func(t *testing.T) {
			raw := requestSecretContract(t, srv, http.MethodGet, path, "", http.StatusOK)
			for _, secret := range hidden {
				assert.NotContains(t, string(raw), secret)
			}
			if path == "/api/v1/pipeline" {
				var composite map[string]json.RawMessage
				require.NoError(t, json.Unmarshal(raw, &composite))
				raw = composite["outputs"]
			}
			if path != "/api/v1/pipeline/outputs/"+name {
				var entries map[string]json.RawMessage
				require.NoError(t, json.Unmarshal(raw, &entries))
				raw = entries[name]
			}
			got := assertSecretContractResponse(t, raw, public, fields, hidden)
			assert.Equal(t, before.Name, got.Name)
			assert.Equal(t, before.Version, got.Version)
			assert.Equal(t, before.Provisioned, got.Provisioned)
			assert.True(t, before.UpdatedAt.Equal(got.UpdatedAt))
			after, err := db.GetOutputConfig(t.Context(), name)
			require.NoError(t, err)
			assert.Equal(t, before, after)
			stored, err := json.Marshal(after)
			require.NoError(t, err)
			assert.Equal(t, string(snapshot), string(stored))
			assert.NotContains(t, string(stored), `"secret_fields"`)
		})
	}
}
