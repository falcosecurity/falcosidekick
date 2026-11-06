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

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"
	"go.yaml.in/yaml/v4"
)

// Load reads configuration from a YAML file and environment variables.
// When configPath is empty, only defaults and environment variables apply.
// Prefix: FALCOSIDEKICK_.
func Load(configPath string) (*Config, error) {
	v := viper.New()

	applyDefaults(v)

	if configPath != "" {
		settings, err := readCoreConfig(configPath)
		if err != nil {
			return nil, err
		}
		if err := v.MergeConfigMap(settings); err != nil {
			return nil, fmt.Errorf("config read %q: %w", configPath, err)
		}
	}

	v.SetEnvPrefix("FALCOSIDEKICK")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	var cfg Config
	if err := v.Unmarshal(&cfg, viper.DecodeHook(
		mapstructure.ComposeDecodeHookFunc(
			mapstructure.StringToTimeDurationHookFunc(),
			mapstructure.StringToSliceHookFunc(","),
		),
	), func(dc *mapstructure.DecoderConfig) {
		dc.ErrorUnused = true
	}); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}

	return &cfg, nil
}

// readCoreConfig parses the core file with the YAML library and safe errors of the output files:
// viper's own parser returns messages that quote the input.
func readCoreConfig(path string) (map[string]any, error) {
	data, err := os.ReadFile(path) //nolint:gosec // user-provided config file path
	if err != nil {
		return nil, fmt.Errorf("config read %q: %w", path, err)
	}
	var settings map[string]any
	if err := yaml.Unmarshal(data, &settings); err != nil {
		return nil, fmt.Errorf("config read %q: %w", path, safeYAMLError(err))
	}
	return settings, nil
}
