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
	"strconv"
	"strings"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
)

func extractLabels(extraLabels []string, evt *event.Event) map[string]string {
	labels := map[string]string{
		"rule":     evt.Rule,
		"source":   evt.Source,
		"priority": string(evt.Priority),
	}

	if evt.Hostname != "" {
		labels["hostname"] = evt.Hostname
	}

	if tags := shared.FormatTags(evt.Tags, ","); tags != "" {
		labels["tags"] = tags
	}

	if ns, ok := evt.OutputFields["k8s.ns.name"]; ok {
		labels["k8s_ns_name"] = fmt.Sprintf("%v", ns)
	}
	if pod, ok := evt.OutputFields["k8s.pod.name"]; ok {
		labels["k8s_pod_name"] = fmt.Sprintf("%v", pod)
	}

	for _, field := range extraLabels {
		if v, ok := evt.OutputFields[field]; ok {
			labels[shared.SanitizeLabel(field)] = fmt.Sprintf("%v", v)
		}
	}

	return labels
}

// serializeLabels creates a deterministic string key for stream grouping.
func serializeLabels(labels map[string]string) string {
	keys := shared.SortMapKeys(labels)
	pairs := make([]string, len(keys))
	for i, k := range keys {
		pairs[i] = k + "=" + strconv.Quote(labels[k])
	}
	return "{" + strings.Join(pairs, ",") + "}"
}
