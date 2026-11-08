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
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/falcosecurity/falcosidekick/internal/utils"
)

// yamlTypeMismatchLine matches yaml.v3 type errors, which quote a prefix of the scalar.
var yamlTypeMismatchLine = regexp.MustCompile(`^line (\d+): cannot unmarshal `)

// OutputsConfig holds output definitions loaded from one or more output files and their paths.
type OutputsConfig struct {
	Outputs map[string]map[string]any `yaml:"outputs"`
	Paths   []string                  `yaml:"-"`
}

// LoadOutputs reads output configurations from one or more YAML files.
// Files are processed left-to-right; same output names deep-merge.
func LoadOutputs(paths []string) (*OutputsConfig, error) {
	merged := &OutputsConfig{
		Paths:   paths,
		Outputs: make(map[string]map[string]any),
	}

	for _, path := range paths {
		data, err := os.ReadFile(path) //nolint:gosec // user-provided config file path
		if err != nil {
			return nil, fmt.Errorf("read output config %q: %w", path, err)
		}

		var raw map[string]any
		if err := yaml.Unmarshal(data, &raw); err != nil {
			return nil, fmt.Errorf("parse output config %q: %w", path, safeYAMLError(err))
		}

		for key := range raw {
			if key != "outputs" {
				return nil, fmt.Errorf("output config %q: unknown top-level key %q (only \"outputs\" is allowed)", path, key)
			}
		}

		var partial OutputsConfig
		if err := yaml.Unmarshal(data, &partial); err != nil {
			return nil, fmt.Errorf("parse output config %q: %w", path, safeYAMLError(err))
		}

		for name, srcCfg := range partial.Outputs {
			dstCfg, exists := merged.Outputs[name]
			if !exists {
				merged.Outputs[name] = srcCfg
				continue
			}
			utils.DeepMergeMap(dstCfg, srcCfg)
		}
	}

	return merged, nil
}

func safeYAMLError(err error) error {
	typeErr, ok := errors.AsType[*yaml.TypeError](err)
	if !ok {
		return err
	}
	lines := make([]string, len(typeErr.Errors))
	for i, line := range typeErr.Errors {
		lines[i] = "invalid structure"
		if m := yamlTypeMismatchLine.FindStringSubmatch(line); m != nil {
			lines[i] = "line " + m[1] + ": invalid structure"
		}
	}
	return errors.New("yaml: " + strings.Join(lines, "; "))
}
