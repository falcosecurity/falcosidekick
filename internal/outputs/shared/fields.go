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
	"net/url"
	"sort"
	"strings"
	"unicode/utf8"
)

// FalcosidekickIconURL is the default avatar or image of chat outputs.
const FalcosidekickIconURL = "https://raw.githubusercontent.com/falcosecurity/falcosidekick/master/imgs/falcosidekick_color.png"

// IsAbsoluteHTTPURL reports whether raw is an absolute http or https URL.
func IsAbsoluteHTTPURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

// SortMapKeys returns the keys of a string-keyed map sorted alphabetically.
func SortMapKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// TruncateRunes truncates a string to maxRunes and appends an ellipsis marker if truncated.
func TruncateRunes(s string, maxRunes int) string {
	runes := []rune(s)
	if len(runes) <= maxRunes {
		return s
	}
	if maxRunes <= 3 {
		return string(runes[:maxRunes])
	}
	return string(runes[:maxRunes-3]) + "..."
}

// TruncateBytes truncates s to at most maxBytes bytes on a UTF-8 boundary, ending with "..." when it cuts.
func TruncateBytes(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	const marker = "..."
	if maxBytes < len(marker) {
		return ""
	}
	cut := maxBytes - len(marker)
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + marker
}

// FormatTags sorts tags alphabetically and joins them with the given separator.
func FormatTags(tags []string, sep string) string {
	if len(tags) == 0 {
		return ""
	}
	sorted := make([]string, len(tags))
	copy(sorted, tags)
	sort.Strings(sorted)
	return strings.Join(sorted, sep)
}
