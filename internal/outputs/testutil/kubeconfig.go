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

package testutil

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// WriteKubeconfig writes a kubeconfig for server with a bearer token, trusting
// caData (base64 PEM) when set, and returns its path.
func WriteKubeconfig(t *testing.T, server, caData, token string) string {
	t.Helper()
	cluster := "    insecure-skip-tls-verify: false\n"
	if caData != "" {
		cluster = "    certificate-authority-data: " + caData + "\n"
	}
	content := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: test
  cluster:
    server: %s
%susers:
- name: test
  user:
    token: %s
contexts:
- name: test
  context:
    cluster: test
    user: test
current-context: test
`, server, cluster, token)
	path := filepath.Join(t.TempDir(), "kubeconfig")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}
