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

package loki

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

// Built-in stream labels. They are few and bounded; rule, tags and pod stay in the log line.
const (
	labelSource    = "source"
	labelPriority  = "priority"
	labelLevel     = "level"
	labelHostname  = "hostname"
	labelNamespace = "k8s_ns_name"

	fieldNamespace = "k8s.ns.name"
)

var builtinLabels = map[string]bool{
	labelSource: true, labelPriority: true, labelLevel: true, labelHostname: true, labelNamespace: true,
}

// levels maps a priority to the level names Grafana recognizes for log coloring.
var levels = map[event.Priority]string{
	event.PriorityEmergency:     "critical",
	event.PriorityAlert:         "critical",
	event.PriorityCritical:      "critical",
	event.PriorityError:         "error",
	event.PriorityWarning:       "warning",
	event.PriorityNotice:        "info",
	event.PriorityInformational: "info",
	event.PriorityDebug:         "debug",
}

// labelName maps proc.aname[2] to proc_aname_2; the result must still be a valid label name.
var labelName = strings.NewReplacer(".", "_", "[", "_", "]", "")

// validLabelName is the Prometheus and Loki label grammar.
var validLabelName = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// labelField is an output field added as a stream label.
type labelField struct {
	field string
	label string
}

func parseLabelFields(fields []string) ([]labelField, utils.ValidationErrors) {
	var errs utils.ValidationErrors
	parsed := make([]labelField, 0, len(fields))
	seen := make(map[string]string, len(fields))
	for i, field := range fields {
		key := fmt.Sprintf("label_fields[%d]", i)
		label := labelName.Replace(field)
		switch previous, duplicate := seen[label]; {
		case !validLabelName.MatchString(label):
			errs.Add(key, fmt.Sprintf("%q does not make a valid label name: letters, digits, `_`, `.` and an index such as [2], not starting with a digit", field))
		case strings.HasPrefix(label, "__"):
			errs.Add(key, fmt.Sprintf("%q makes a label starting with __, reserved by Loki", field))
		case builtinLabels[label]:
			errs.Add(key, fmt.Sprintf("%q makes the built-in label %s", field, label))
		case duplicate:
			errs.Add(key, fmt.Sprintf("%q and %q make the same label %s", previous, field, label))
		default:
			seen[label] = field
			parsed = append(parsed, labelField{field: field, label: label})
		}
	}
	return parsed, errs
}

func extractLabels(labelFields []labelField, evt *event.Event) map[string]string {
	labels := map[string]string{
		labelSource:   evt.Source,
		labelPriority: evt.Priority.String(),
		labelLevel:    levels[evt.Priority],
	}

	if evt.Hostname != "" {
		labels[labelHostname] = evt.Hostname
	}

	if ns, ok := evt.OutputFields[fieldNamespace]; ok {
		labels[labelNamespace] = fmt.Sprintf("%v", ns)
	}

	for _, f := range labelFields {
		if v, ok := evt.OutputFields[f.field]; ok {
			labels[f.label] = fmt.Sprintf("%v", v)
		}
	}

	return labels
}

func serializeLabels(labels map[string]string) string {
	keys := shared.SortMapKeys(labels)
	pairs := make([]string, len(keys))
	for i, k := range keys {
		pairs[i] = k + "=" + strconv.Quote(labels[k])
	}
	return "{" + strings.Join(pairs, ",") + "}"
}
