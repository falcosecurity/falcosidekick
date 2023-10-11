// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package outputs

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/types"
)

func TestNewDatadogPayload(t *testing.T) {
	expectedOutput := `{"title":"Test rule","text":"This is a test from falcosidekick","alert_type":"info","source_type_name":"falco","tags":["proc.name:falcosidekick", "source:syscalls", "hostname:test-host", "test", "example"]}`
	var f types.FalcoPayload
	json.Unmarshal([]byte(falcoTestInput), &f)
	s, _ := json.Marshal(newDatadogPayload(f))

	var o1, o2 datadogPayload
	require.Nil(t, json.Unmarshal([]byte(expectedOutput), &o1))
	require.Nil(t, json.Unmarshal(s, &o2))

	require.Equal(t, o1, o2)
}
