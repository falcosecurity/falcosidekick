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

package gcppubsub

import (
	"encoding/json"
	"fmt"
	"maps"
	"strconv"
	"strings"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

// eventAttributes are the event fields message_attributes can name; any other name is an output field.
var eventAttributes = map[string]func(*event.Event) string{
	"priority": func(e *event.Event) string { return e.Priority.String() },
	"rule":     func(e *event.Event) string { return e.Rule },
	"source":   func(e *event.Event) string { return e.Source },
	"tags":     func(e *event.Event) string { return strings.Join(e.Tags, ",") },
	"hostname": func(e *event.Event) string { return e.Hostname },
}

var defaultMessageAttributes = []string{"priority", "rule", "source", "tags", "hostname"}

// validateMessageAttributes refuses names Pub/Sub rejects, repeated names, names that are also
// static attributes, and more attributes per message than Pub/Sub accepts.
func validateMessageAttributes(names []string, static map[string]string) utils.ValidationErrors {
	var errs utils.ValidationErrors
	if len(names)+len(static) > maxAttributes {
		errs.Add("", fmt.Sprintf("at most %d attributes together with attributes", maxAttributes))
	}
	seen := make(map[string]bool, len(names))
	for _, name := range names {
		if reason := checkAttributeName(name); reason != "" {
			errs.Add("", fmt.Sprintf("%q: %s", name, reason))
			continue
		}
		if seen[name] {
			errs.Add("", fmt.Sprintf("%q is listed twice", name))
			continue
		}
		seen[name] = true
		if _, ok := static[name]; ok {
			errs.Add("", fmt.Sprintf("%q is also a static attribute", name))
		}
	}
	return errs
}

// messageAttributes returns the static attributes plus the listed event values the event has,
// leaving out empty values and values Pub/Sub would refuse.
func messageAttributes(evt *event.Event, static map[string]string, names []string) map[string]string {
	if len(static) == 0 && len(names) == 0 {
		return nil
	}
	attrs := make(map[string]string, len(static)+len(names))
	maps.Copy(attrs, static)
	for _, name := range names {
		value := eventValue(evt, name)
		if value != "" && len(value) <= maxAttributeValBytes {
			attrs[name] = value
		}
	}
	return attrs
}

func eventValue(evt *event.Event, name string) string {
	if value, ok := eventAttributes[name]; ok {
		return value(evt)
	}
	switch v := evt.OutputFields[name].(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case int:
		return strconv.Itoa(v)
	case int64:
		return strconv.FormatInt(v, 10)
	}
	return ""
}
