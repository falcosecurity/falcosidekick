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
	"math"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
)

const (
	safeInvalidValue = "invalid value"
	safeExpectedMap  = "invalid type, expected map"
)

// mapstructure reports these two failures as untyped errors with fixed texts.
var (
	safeUnknownKeysText = regexp.MustCompile(`(?s)^has invalid keys: (.*)$`)
	safeExpectedMapText = regexp.MustCompile(`^expected a map or struct, got `)
)

// DecodeFailure is a decode hook failure whose text never contains a submitted value.
type DecodeFailure string

func (f DecodeFailure) Error() string { return string(f) }

// SafeDecodeError returns the failures of a mapstructure decode error as "field: reason", sorted, never
// quoting a submitted value; target names the root.
func SafeDecodeError(err error, target reflect.Type) ValidationErrors {
	root := ""
	if target != nil {
		for target.Kind() == reflect.Pointer {
			target = target.Elem()
		}
		root = target.String()
	}
	errs := safeDecodeErrors(err, root)
	slices.SortFunc(errs, func(a, b ValidationError) int { return strings.Compare(a.Error(), b.Error()) })
	return errs
}

func safeDecodeErrors(err error, root string) ValidationErrors {
	switch e := err.(type) {
	case *mapstructure.DecodeError:
		field := e.Name()
		if field == root { // the root struct is named after its Go type
			field = ""
		}
		return ValidationErrors{{Field: field, Message: safeDecodeReason(e.Unwrap())}}
	case interface{ Unwrap() []error }:
		var errs ValidationErrors
		for _, child := range e.Unwrap() {
			errs = append(errs, safeDecodeErrors(child, root)...)
		}
		return errs
	case interface{ Unwrap() error }:
		if inner := e.Unwrap(); inner != nil {
			return safeDecodeErrors(inner, root)
		}
	}
	return ValidationErrors{{Message: safeInvalidValue}}
}

func safeDecodeReason(err error) string {
	if err == nil {
		return safeInvalidValue
	}
	if failure, ok := errors.AsType[DecodeFailure](err); ok {
		return string(failure)
	}
	if unconvertible, ok := errors.AsType[*mapstructure.UnconvertibleTypeError](err); ok {
		// A map's Go type names an internal value type; the user wrote a map.
		if unconvertible.Expected.Kind() == reflect.Map {
			return safeExpectedMap
		}
		return "invalid type, expected " + unconvertible.Expected.Type().String()
	}
	// mapstructure's ParseError quotes the value.
	if parse, ok := errors.AsType[*mapstructure.ParseError](err); ok {
		switch parse.Expected.Kind() { //nolint:exhaustive // only the kinds a weakly typed string parses into
		case reflect.Bool:
			return "must be true or false"
		case reflect.Float32, reflect.Float64:
			return string(notNumber)
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
			reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
			return string(notInteger)
		}
	}
	text := err.Error()
	if m := safeUnknownKeysText.FindStringSubmatch(text); m != nil {
		return "unknown keys: " + m[1]
	}
	if safeExpectedMapText.MatchString(text) {
		return safeExpectedMap
	}
	return safeInvalidValue
}

// TypeHooks is the conversion set every decoder uses instead of mapstructure's weak typing: text is
// read into booleans, numbers and durations, a number or a boolean into a string, nothing else converts.
func TypeHooks() mapstructure.DecodeHookFunc {
	return mapstructure.ComposeDecodeHookFunc(DurationHook(), BoolHook(), NumberHook(), StringHook(), ListHook())
}

const notDuration = DecodeFailure("must be a duration such as 30s or 1m")

// DurationHook decodes a duration as DurationValue reads it; its reason never quotes the value.
func DurationHook() mapstructure.DecodeHookFuncType {
	durationType := reflect.TypeFor[time.Duration]()
	return func(_ reflect.Type, to reflect.Type, data any) (any, error) {
		if to != durationType {
			return data, nil
		}
		d, err := DurationValue(data)
		if err != nil {
			return nil, err
		}
		return d, nil
	}
}

// DurationValue reads a duration as the decoders and the schema range check do: a string as
// time.ParseDuration, the integer 0 as "0s"; any other number would be nanoseconds and is refused.
func DurationValue(data any) (time.Duration, error) {
	v := reflect.ValueOf(data)
	if !v.IsValid() {
		return 0, notDuration
	}
	if v.Type() == reflect.TypeFor[time.Duration]() {
		return time.Duration(v.Int()), nil
	}
	if isJSONNumber(v.Type()) {
		if n, err := strconv.ParseInt(v.String(), 10, 64); err == nil && n == 0 {
			return 0, nil
		}
		return 0, notDuration
	}
	switch {
	case v.Kind() == reflect.String:
		d, err := time.ParseDuration(v.String())
		if err != nil {
			return 0, notDuration
		}
		return d, nil
	case v.CanInt() && v.Int() == 0, v.CanUint() && v.Uint() == 0:
		return 0, nil
	default:
		return 0, notDuration
	}
}

const notBool = DecodeFailure("must be true or false")

// BoolHook reads a boolean or its text as strconv.ParseBool does; a number is not a boolean.
func BoolHook() mapstructure.DecodeHookFuncType {
	return func(from reflect.Type, to reflect.Type, data any) (any, error) {
		if to.Kind() != reflect.Bool {
			return data, nil
		}
		switch {
		case from.Kind() == reflect.Bool:
			return data, nil
		case from.Kind() == reflect.String && !isJSONNumber(from):
			b, err := strconv.ParseBool(reflect.ValueOf(data).String())
			if err != nil {
				return nil, notBool
			}
			return b, nil
		default:
			return nil, notBool
		}
	}
}

// StringHook takes a number or a boolean as the text of a string field, as YAML reads an unquoted scalar; a map or a list is refused.
func StringHook() mapstructure.DecodeHookFuncType {
	return func(from reflect.Type, to reflect.Type, data any) (any, error) {
		if to.Kind() != reflect.String {
			return data, nil
		}
		v := reflect.ValueOf(data)
		switch from.Kind() {
		case reflect.Bool:
			return strconv.FormatBool(v.Bool()), nil
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			return strconv.FormatInt(v.Int(), 10), nil
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
			return strconv.FormatUint(v.Uint(), 10), nil
		case reflect.Float32, reflect.Float64:
			return strconv.FormatFloat(v.Float(), 'f', -1, 64), nil
		default:
			return data, nil
		}
	}
}

const notList = DecodeFailure("must be a list")

// ListHook refuses a non-list where a list is expected; the core decoder splits environment text first.
func ListHook() mapstructure.DecodeHookFuncType {
	return func(from reflect.Type, to reflect.Type, data any) (any, error) {
		if to.Kind() != reflect.Slice || from.Kind() == reflect.Slice || from.Kind() == reflect.Array {
			return data, nil
		}
		return nil, notList
	}
}

func isJSONNumber(t reflect.Type) bool {
	return t.PkgPath() == jsonPackage && t.Name() == jsonNumber
}

// Numeric decode failures; none quotes the value.
const (
	notInteger  = DecodeFailure("must be an integer")
	notNumber   = DecodeFailure("must be a number")
	outOfRange  = DecodeFailure("is out of range")
	notFinite   = DecodeFailure("must be a finite number")
	twoPow63    = float64(1 << 63)
	maxFloat32  = float64(math.MaxFloat32)
	jsonPackage = "encoding/json"
	jsonNumber  = "Number"
)

// NumberHook refuses numeric conversions that would truncate, wrap or saturate, and booleans into
// numbers; Go leaves an out-of-range float to integer conversion to the architecture.
func NumberHook() mapstructure.DecodeHookFuncType {
	return func(_ reflect.Type, to reflect.Type, data any) (any, error) {
		switch to.Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			n, err := IntegerValue(data)
			if errors.Is(err, ErrNotNumeric) {
				return data, nil
			}
			if err != nil {
				return nil, err
			}
			if reflect.Zero(to).OverflowInt(n) {
				return nil, outOfRange
			}
			return n, nil
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
			if u, ok := data.(uint64); ok {
				if reflect.Zero(to).OverflowUint(u) {
					return nil, outOfRange
				}
				return u, nil
			}
			n, err := IntegerValue(data)
			if errors.Is(err, ErrNotNumeric) {
				return data, nil
			}
			if err != nil {
				return nil, err
			}
			if n < 0 || reflect.Zero(to).OverflowUint(uint64(n)) {
				return nil, outOfRange
			}
			return uint64(n), nil
		case reflect.Float32, reflect.Float64:
			f, err := FloatValue(data)
			if errors.Is(err, ErrNotNumeric) {
				return data, nil
			}
			if err != nil {
				return nil, err
			}
			if to.Kind() == reflect.Float32 && math.Abs(f) > maxFloat32 {
				return nil, outOfRange
			}
			return f, nil
		default:
			return data, nil
		}
	}
}

// ErrNotNumeric marks a value that is neither a number nor a string: the decoder reports its type.
var ErrNotNumeric = errors.New("not numeric")

// IntegerValue converts a decoded number or numeric string to int64, refusing what does not fit exactly.
func IntegerValue(data any) (int64, error) {
	v := reflect.ValueOf(data)
	if !v.IsValid() {
		return 0, ErrNotNumeric
	}
	if isJSONNumber(v.Type()) {
		return parseInteger(v.String())
	}
	switch v.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int(), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		if v.Uint() > math.MaxInt64 {
			return 0, outOfRange
		}
		return int64(v.Uint()), nil //nolint:gosec // checked against MaxInt64 above
	case reflect.Float32, reflect.Float64:
		return floatToInteger(v.Float())
	case reflect.Bool:
		return 0, notInteger
	case reflect.String:
		return parseInteger(v.String())
	default:
		return 0, ErrNotNumeric
	}
}

// FloatValue converts a decoded number or numeric string to a finite float64.
func FloatValue(data any) (float64, error) {
	v := reflect.ValueOf(data)
	if !v.IsValid() {
		return 0, ErrNotNumeric
	}
	var f float64
	switch {
	case isJSONNumber(v.Type()), v.Kind() == reflect.String:
		parsed, err := strconv.ParseFloat(strings.TrimSpace(v.String()), 64)
		if err != nil {
			if errors.Is(err, strconv.ErrRange) {
				return 0, outOfRange
			}
			return 0, notNumber
		}
		f = parsed
	case v.Kind() >= reflect.Int && v.Kind() <= reflect.Int64:
		f = float64(v.Int())
	case v.Kind() >= reflect.Uint && v.Kind() <= reflect.Uintptr:
		f = float64(v.Uint())
	case v.Kind() == reflect.Float32 || v.Kind() == reflect.Float64:
		f = v.Float()
	case v.Kind() == reflect.Bool:
		return 0, notNumber
	default:
		return 0, ErrNotNumeric
	}
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, notFinite
	}
	return f, nil
}

func floatToInteger(f float64) (int64, error) {
	switch {
	case math.IsNaN(f):
		return 0, notInteger
	case f >= twoPow63 || f < -twoPow63:
		return 0, outOfRange
	case f != math.Trunc(f):
		return 0, notInteger
	}
	return int64(f), nil
}

// parseInteger accepts base prefixes, as mapstructure does, and a float form that holds an exact integer.
func parseInteger(s string) (int64, error) {
	s = strings.TrimSpace(s)
	n, err := strconv.ParseInt(s, 0, 64)
	if err == nil {
		return n, nil
	}
	if errors.Is(err, strconv.ErrRange) {
		return 0, outOfRange
	}
	f, ferr := strconv.ParseFloat(s, 64)
	if ferr != nil {
		if errors.Is(ferr, strconv.ErrRange) {
			return 0, outOfRange
		}
		return 0, notInteger
	}
	return floatToInteger(f)
}
