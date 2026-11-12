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
	"fmt"
	"strconv"
	"time"
)

// IntRange is an inclusive range of integers.
type IntRange struct{ Min, Max int }

// Contains reports whether v lies in the range.
func (r IntRange) Contains(v int) bool { return v >= r.Min && v <= r.Max }

// Message is the validation message for a value outside the range.
func (r IntRange) Message() string {
	return fmt.Sprintf("must be an integer between %d and %d", r.Min, r.Max)
}

// Check adds the range message for field when v lies outside the range.
func (r IntRange) Check(errs *ValidationErrors, field string, v int) {
	if !r.Contains(v) {
		errs.Add(field, r.Message())
	}
}

// FloatRange is an inclusive range of finite numbers.
type FloatRange struct{ Min, Max float64 }

// Contains reports whether v lies in the range; NaN never does.
func (r FloatRange) Contains(v float64) bool { return v >= r.Min && v <= r.Max }

// Message is the validation message for a value outside the range.
func (r FloatRange) Message() string {
	return "must be a number between " + strconv.FormatFloat(r.Min, 'g', -1, 64) +
		" and " + strconv.FormatFloat(r.Max, 'g', -1, 64)
}

// Check adds the range message for field when v lies outside the range.
func (r FloatRange) Check(errs *ValidationErrors, field string, v float64) {
	if !r.Contains(v) {
		errs.Add(field, r.Message())
	}
}

// DurationRange is an inclusive range of durations.
type DurationRange struct{ Min, Max time.Duration }

// Contains reports whether v lies in the range.
func (r DurationRange) Contains(v time.Duration) bool { return v >= r.Min && v <= r.Max }

// Message is the validation message for a value outside the range.
func (r DurationRange) Message() string {
	return fmt.Sprintf("must be a duration between %s and %s", FormatDuration(r.Min), FormatDuration(r.Max))
}

// FormatDuration writes d in its shortest unit when it is a whole number of hours, minutes or
// seconds ("1h", not "1h0m0s"), and as time.Duration.String otherwise.
func FormatDuration(d time.Duration) string {
	for _, unit := range []struct {
		name string
		size time.Duration
	}{{"h", time.Hour}, {"m", time.Minute}, {"s", time.Second}} {
		if d != 0 && d%unit.size == 0 {
			return strconv.FormatInt(int64(d/unit.size), 10) + unit.name
		}
	}
	return d.String()
}

// Check adds the range message for field when v lies outside the range.
func (r DurationRange) Check(errs *ValidationErrors, field string, v time.Duration) {
	if !r.Contains(v) {
		errs.Add(field, r.Message())
	}
}
