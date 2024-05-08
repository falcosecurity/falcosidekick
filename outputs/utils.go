// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import "sort"

func getSortedStringKeys(m map[string]interface{}) []string {
	var keys []string
	for i, j := range m {
		switch j.(type) {
		case string:
			keys = append(keys, i)
		default:
			continue
		}
	}
	sort.Strings(keys)
	return keys
}
