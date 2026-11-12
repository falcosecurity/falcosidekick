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

// DecodeDriverConfig decodes a raw config map into a typed driver config struct.
// The target struct should include a Runtime output.RuntimeConfig field to receive runtime override fields.
// Rejects unknown keys, squashes embedded structs, and reads each value with utils.TypeHooks. A null
// is an omitted setting: an unknown key is refused even when null, and nulls are removed from raw after a successful decode.
// Returned decode errors name fields and reasons, never submitted values.
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
