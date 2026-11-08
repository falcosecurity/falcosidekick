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
	"regexp"
	"strings"
)

var labelSanitizer = regexp.MustCompile(`[^a-zA-Z0-9_]`)

// SanitizeLabel replaces characters not allowed in Prometheus/Loki label names,
// collapses double underscores, trims leading/trailing underscores, and
// prepends underscore if the name starts with a digit.
// Label names must match [a-zA-Z_][a-zA-Z0-9_]*.
func SanitizeLabel(s string) string {
	result := labelSanitizer.ReplaceAllString(s, "_")
	result = strings.Trim(result, "_")
	for strings.Contains(result, "__") {
		result = strings.ReplaceAll(result, "__", "_")
	}
	if result != "" && result[0] >= '0' && result[0] <= '9' {
		result = "_" + result
	}
	return result
}
