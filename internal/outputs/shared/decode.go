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
	"reflect"
	"regexp"
	"slices"
	"strings"

	"github.com/go-viper/mapstructure/v2"
)

const safeInvalidValue = "invalid value"

// mapstructure reports these two failures as untyped errors with fixed texts.
var (
	safeUnknownKeysText = regexp.MustCompile(`(?s)^has invalid keys: (.*)$`)
	safeExpectedMapText = regexp.MustCompile(`^expected a map or struct, got `)
)

// safeDecodeFailure is a decode failure whose text never contains a submitted value.
type safeDecodeFailure string

func (f safeDecodeFailure) Error() string { return string(f) }

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
		return safeDecodeError(err, reflect.TypeOf(result))
	}
	return nil
}

// safeDecodeError returns sorted "field: reason" messages without submitted values.
func safeDecodeError(err error, target reflect.Type) error {
	root := ""
	if target != nil {
		for target.Kind() == reflect.Pointer {
			target = target.Elem()
		}
		root = target.String()
	}
	messages := safeDecodeMessages(err, root)
	slices.Sort(messages)
	return errors.New(strings.Join(messages, "; "))
}

func safeDecodeMessages(err error, root string) []string {
	switch e := err.(type) {
	case *mapstructure.DecodeError:
		field := e.Name()
		if field == root { // the root struct is named after its Go type
			field = ""
		}
		return []string{safeWithField(field, safeDecodeReason(e.Unwrap()))}
	case interface{ Unwrap() []error }:
		var messages []string
		for _, child := range e.Unwrap() {
			messages = append(messages, safeDecodeMessages(child, root)...)
		}
		return messages
	case interface{ Unwrap() error }:
		if inner := e.Unwrap(); inner != nil {
			return safeDecodeMessages(inner, root)
		}
	}
	return []string{safeInvalidValue}
}

func safeDecodeReason(err error) string {
	if err == nil {
		return safeInvalidValue
	}
	if failure, ok := errors.AsType[safeDecodeFailure](err); ok {
		return string(failure)
	}
	if unconvertible, ok := errors.AsType[*mapstructure.UnconvertibleTypeError](err); ok {
		return "invalid type, expected " + unconvertible.Expected.Type().String()
	}
	text := err.Error()
	if m := safeUnknownKeysText.FindStringSubmatch(text); m != nil {
		return "unknown keys: " + m[1]
	}
	if safeExpectedMapText.MatchString(text) {
		return "invalid type, expected map"
	}
	return safeInvalidValue
}

func safeWithField(field, reason string) string {
	if field == "" {
		return reason
	}
	return field + ": " + reason
}
