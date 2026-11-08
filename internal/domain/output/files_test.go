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

package output

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCollectFilePaths(t *testing.T) {
	fields := []SchemaField{
		{Name: "token", Type: "string", Secret: true},
		{Name: "password", Type: "map", Secret: true},
		{Name: "tls.ca_file", Type: "string", File: true},
		{Name: "certs", Type: "list", File: true},
		{Name: "headers", Type: "map", EntryFields: []SchemaField{
			{Name: "files", Type: "list", File: true},
		}},
	}
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
			err := CollectFilePaths(tt.cfg, fields, paths)
			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.want, paths, "paths keeps what was collected before an error")
		})
	}
}
