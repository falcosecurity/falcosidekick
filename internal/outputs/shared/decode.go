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
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/mitchellh/mapstructure"
)

// Decoder messages embed submitted values and mapstructure exposes them only as text.
// Each one is rebuilt from a closed list of shapes, so unknown text yields no content.
var (
	decodeTypeMismatch = regexp.MustCompile(`^'([^']*)' expected type '([^']*)', got unconvertible type `)
	decodeExpectedMap  = regexp.MustCompile(`^'([^']*)' expected a map, got `)
	decodeUnknownKeys  = regexp.MustCompile(`(?s)^'([^']*)' has invalid keys: (.*)$`)
	decodeNamedFailure = regexp.MustCompile(`^(?:error decoding|cannot parse) '([^']*)'`)
	// Fixed decodeValueSourcesHook texts, shared by headers and query_params; property names come from the ValueSources definition.
	decodeValueSourcesFailure = regexp.MustCompile(`^error decoding '([^']*)': (entry must be a map|property names must be strings|duplicate property \w+|\w+: must be a list of strings|unknown property)$`)
)

// DecodeDriverConfig decodes a raw config map into a typed driver config struct.
// The target struct should include a Runtime output.RuntimeConfig field to receive runtime override fields.
// Rejects unknown keys, handles duration strings, and squashes embedded structs.
// Returned decode errors name fields and reasons, never submitted values.
func DecodeDriverConfig(raw map[string]any, result any) error {
	dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		ErrorUnused:      true,
		WeaklyTypedInput: true,
		Squash:           true,
		DecodeHook: mapstructure.ComposeDecodeHookFunc(
			mapstructure.StringToTimeDurationHookFunc(),
			decodeValueSourcesHook,
		),
		Result: result,
	})
	if err != nil {
		return fmt.Errorf("decoder init: %w", err)
	}
	if err := dec.Decode(raw); err != nil {
		return safeDecodeError(err)
	}
	return nil
}

func safeDecodeError(err error) error {
	messages := []string{err.Error()}
	if decodeErr, ok := errors.AsType[*mapstructure.Error](err); ok {
		messages = decodeErr.Errors
	}
	safe := make([]string, len(messages))
	for i, message := range messages {
		safe[i] = safeDecodeMessage(message)
	}
	slices.Sort(safe)
	return errors.New(strings.Join(safe, "; "))
}

func safeDecodeMessage(message string) string {
	if m := decodeUnknownKeys.FindStringSubmatch(message); m != nil {
		return withField(m[1], "unknown keys: "+m[2])
	}
	if m := decodeTypeMismatch.FindStringSubmatch(message); m != nil {
		return withField(m[1], "invalid type, expected "+m[2])
	}
	if m := decodeExpectedMap.FindStringSubmatch(message); m != nil {
		return withField(m[1], "invalid type, expected map")
	}
	if m := decodeValueSourcesFailure.FindStringSubmatch(message); m != nil {
		return withField(m[1], m[2])
	}
	if m := decodeNamedFailure.FindStringSubmatch(message); m != nil {
		return withField(m[1], "invalid value")
	}
	return "invalid value"
}

func withField(field, reason string) string {
	if field == "" {
		return reason
	}
	return field + ": " + reason
}
