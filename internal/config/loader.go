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
	"reflect"
	"strings"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"
	"go.yaml.in/yaml/v4"

	"github.com/falcosecurity/falcosidekick/internal/utils"
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
		// viper drops null keys: decode the file alone first, so a null under an unknown key is refused.
		if err := checkFileKeys(settings); err != nil {
			return nil, err
		}
		if err := v.MergeConfigMap(settings); err != nil {
			return nil, fmt.Errorf("config read %q: %w", configPath, err)
		}
	}

	v.SetEnvPrefix("FALCOSIDEKICK")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
	if err := bindEnv(v, reflect.TypeFor[Config](), ""); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}

	var cfg Config
	if err := v.Unmarshal(&cfg, viper.DecodeHook(decodeHook()), func(dc *mapstructure.DecoderConfig) {
		dc.ErrorUnused = true
		dc.WeaklyTypedInput = false
	}); err != nil {
		return nil, fmt.Errorf("config: %w", utils.SafeDecodeError(err, reflect.TypeFor[Config]()))
	}

	return &cfg, nil
}

// bindEnv registers every key of t: viper's Unmarshal reads the environment only for keys it knows,
// so a key without a default or a file value would otherwise ignore its variable.
func bindEnv(v *viper.Viper, t reflect.Type, prefix string) error {
	for field := range t.Fields() {
		name, opts, _ := strings.Cut(field.Tag.Get("mapstructure"), ",")
		if name == "-" || !field.IsExported() {
			continue
		}
		ft := field.Type
		if ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		if opts == "squash" {
			if err := bindEnv(v, ft, prefix); err != nil {
				return err
			}
			continue
		}
		if ft.Kind() == reflect.Struct {
			if err := bindEnv(v, ft, prefix+name+"."); err != nil {
				return err
			}
			continue
		}
		if err := v.BindEnv(prefix + name); err != nil {
			return err
		}
	}
	return nil
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

// decodeHook splits a comma-separated list, the form the environment gives one, before the shared type hooks.
func decodeHook() mapstructure.DecodeHookFunc {
	return mapstructure.ComposeDecodeHookFunc(
		mapstructure.StringToSliceHookFunc(","),
		utils.TypeHooks(),
	)
}

// checkFileKeys decodes the core file alone, nulls included, and reports unknown keys and invalid values as Load does.
func checkFileKeys(settings map[string]any) error {
	var cfg Config
	dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook:  decodeHook(),
		ErrorUnused: true,
		Result:      &cfg,
	})
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	if err := dec.Decode(settings); err != nil {
		return fmt.Errorf("config: %w", utils.SafeDecodeError(err, reflect.TypeFor[Config]()))
	}
	return nil
}
