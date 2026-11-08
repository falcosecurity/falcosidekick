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
	"fmt"
	"os"
	"strings"

	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

// ResolveSecrets reads file-backed secrets for fields marked Secret in the schema.
// For each Secret field, if <field>_file is set and <field> is empty, the file
// content replaces the field value. Trailing newlines are stripped.
func ResolveSecrets(outputName string, cfg map[string]any, schema output.Schema) error {
	for _, field := range schema.Fields {
		if !field.Secret {
			continue
		}

		parent, leafKey := utils.NavigateMap(cfg, field.Name)
		if parent == nil {
			continue
		}

		fileKey := leafKey + "_file"
		filePath, ok := parent[fileKey].(string)
		if !ok || filePath == "" {
			continue
		}

		if v, ok := parent[leafKey].(string); ok && v != "" {
			delete(parent, fileKey)
			continue
		}

		data, err := os.ReadFile(filePath) //nolint:gosec // reading user-configured secret file
		if err != nil {
			return fmt.Errorf("output %q: secret %q: read %q: %w", outputName, field.Name, filePath, err)
		}

		parent[leafKey] = strings.TrimRight(string(data), "\n\r")
		delete(parent, fileKey)
	}
	return nil
}
