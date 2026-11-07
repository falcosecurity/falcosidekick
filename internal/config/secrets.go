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
	"strings"

	"github.com/falcosecurity/falcosidekick/internal/catalog"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

// ResolvedOutputs returns copies of outputs with every <field>_file replaced by the file content,
// to build the outputs from. The configs passed in keep the paths as written: that is what is stored.
func ResolvedOutputs(outputs map[string]map[string]any, cat *catalog.Catalog) (map[string]map[string]any, error) {
	resolved := make(map[string]map[string]any, len(outputs))
	for name, cfg := range outputs {
		outputType, ok := cat.Get(name)
		if !ok {
			return nil, fmt.Errorf("unknown output type %q", name)
		}
		resolvedCfg := utils.DeepCopyMap(cfg)
		if err := ResolveSecrets(name, resolvedCfg, outputType.Schema); err != nil {
			return nil, err
		}
		resolved[name] = resolvedCfg
	}
	return resolved, nil
}

// ResolveSecrets fills empty Secret fields from their <field>_file counterparts.
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

		// The error names the field, not the path or the OS error: the path can arrive through the API.
		data, err := utils.ReadRegularFile(filePath)
		if err != nil {
			return fmt.Errorf("output %q: %s_file: %s", outputName, field.Name, utils.FileProblem(err))
		}

		parent[leafKey] = strings.TrimRight(string(data), "\n\r")
		delete(parent, fileKey)
	}
	return nil
}
