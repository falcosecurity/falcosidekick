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

package hacktesting

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// archivedModules are archived upstream; each line names the maintained replacement.
var archivedModules = map[string]string{
	"github.com/mitchellh/mapstructure":  "github.com/go-viper/mapstructure/v2",
	"github.com/mitchellh/copystructure": "internal/utils.DeepCopyMap",
	"gopkg.in/yaml.v3":                   "go.yaml.in/yaml/v4",
}

func TestGoModRequiresNoArchivedModule(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "go.mod"))
	require.NoError(t, err)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		module := fields[0]
		if module == "require" && len(fields) > 1 {
			module = fields[1]
		}
		replacement, archived := archivedModules[module]
		assert.False(t, archived, "go.mod requires archived %s; use %s", module, replacement)
	}
}
