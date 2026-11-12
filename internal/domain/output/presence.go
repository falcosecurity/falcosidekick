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

package output

import (
	"errors"
	"strings"
	"time"

	"github.com/falcosecurity/falcosidekick/internal/utils"
)

// NormalizeConfig applies the presence rule to a raw output config in place, before it is decoded: ""
// unsets a string or enum field with a default, a present value must lie within Min and Max, and a
// duration is read as the decoder reads it. Nulls are left for the decoder; keys match regardless of case.
func (s Schema) NormalizeConfig(cfg map[string]any) utils.ValidationErrors {
	var errs utils.ValidationErrors
	for i := range s.Fields {
		field := &s.Fields[i]
		parent, key, ok := lookupFold(cfg, field.Name)
		if !ok {
			continue
		}
		value := parent[key]
		if value == "" && field.Default != nil && (field.Type == typeString || field.Type == "enum") {
			delete(parent, key)
			continue
		}
		if msg := field.rangeProblem(value); msg != "" {
			errs.Add(field.Name, msg)
		}
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

// rangeProblem returns why value is outside the field's range; "" when inside, unranged, or of a type the decoder reports.
func (f *SchemaField) rangeProblem(value any) string {
	switch lo := f.Min.(type) {
	case int:
		hi, _ := f.Max.(int)
		n, err := utils.IntegerValue(value)
		if errors.Is(err, utils.ErrNotNumeric) {
			return ""
		}
		if err != nil {
			return err.Error()
		}
		r := utils.IntRange{Min: lo, Max: hi}
		if n < int64(r.Min) || n > int64(r.Max) {
			return r.Message()
		}
	case float64:
		hi, _ := f.Max.(float64)
		v, err := utils.FloatValue(value)
		if errors.Is(err, utils.ErrNotNumeric) {
			return ""
		}
		if err != nil {
			return err.Error()
		}
		if r := (utils.FloatRange{Min: lo, Max: hi}); !r.Contains(v) {
			return r.Message()
		}
	case string:
		d, err := utils.DurationValue(value)
		if err != nil {
			return "" // the decoder reports the format
		}
		minimum, _ := time.ParseDuration(lo)
		maxText, _ := f.Max.(string)
		maximum, _ := time.ParseDuration(maxText)
		if r := (utils.DurationRange{Min: minimum, Max: maximum}); !r.Contains(d) {
			return r.Message()
		}
	}
	return ""
}

// lookupFold finds the dotted path in cfg, matching each key regardless of case.
func lookupFold(cfg map[string]any, path string) (parent map[string]any, key string, ok bool) {
	parts := strings.Split(path, ".")
	current := cfg
	for i, part := range parts {
		found := ""
		for k := range current {
			if strings.EqualFold(k, part) {
				found = k
				break
			}
		}
		if found == "" {
			return nil, "", false
		}
		if i == len(parts)-1 {
			return current, found, true
		}
		child, isMap := current[found].(map[string]any)
		if !isMap {
			return nil, "", false
		}
		current = child
	}
	return nil, "", false
}

// WithIntRange sets the field's Min and Max from r.
func (f SchemaField) WithIntRange(r utils.IntRange) SchemaField { //nolint:gocritic // a value receiver lets schema literals chain it
	f.Min, f.Max = r.Min, r.Max
	return f
}

// WithFloatRange sets the field's Min and Max from r.
func (f SchemaField) WithFloatRange(r utils.FloatRange) SchemaField { //nolint:gocritic // a value receiver lets schema literals chain it
	f.Min, f.Max = r.Min, r.Max
	return f
}

// WithDurationRange sets the field's Min and Max from r, as duration strings.
func (f SchemaField) WithDurationRange(r utils.DurationRange) SchemaField { //nolint:gocritic // a value receiver lets schema literals chain it
	f.Min, f.Max = utils.FormatDuration(r.Min), utils.FormatDuration(r.Max)
	return f
}
