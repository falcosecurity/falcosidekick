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

package utils

import (
	"errors"
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

// DecodeFailure is a decode hook failure whose text never contains a submitted value.
type DecodeFailure string

func (f DecodeFailure) Error() string { return string(f) }

// SafeDecodeError returns the sorted "field: reason" messages of a mapstructure decode error,
// never a submitted value. target is the decoded type, whose name mapstructure uses for the root.
func SafeDecodeError(err error, target reflect.Type) error {
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
	if failure, ok := errors.AsType[DecodeFailure](err); ok {
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
