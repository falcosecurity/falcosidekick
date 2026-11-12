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

package shared

import (
	"fmt"
	"reflect"

	"github.com/go-viper/mapstructure/v2"

	"github.com/falcosecurity/falcosidekick/internal/utils"
)

// DecodeDriverConfig decodes raw into result, a struct with a Runtime output.RuntimeConfig field: unknown keys are refused even when
// null, embedded structs are squashed, values go through utils.TypeHooks, nulls leave raw once decoded, and errors never quote values.
func DecodeDriverConfig(raw map[string]any, result any) error {
	dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		ErrorUnused: true,
		Squash:      true,
		DecodeHook: mapstructure.ComposeDecodeHookFunc(
			utils.TypeHooks(),
			decodeValueSourcesHook,
		),
		Result: result,
	})
	if err != nil {
		return fmt.Errorf("decoder init: %w", err)
	}
	if err := dec.Decode(raw); err != nil {
		return utils.SafeDecodeError(err, reflect.TypeOf(result))
	}
	utils.DropNulls(raw)
	return nil
}
