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

//go:build e2e

package e2e

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

// recordingTB records Fatalf and Skipf instead of stopping the test.
type recordingTB struct {
	testing.TB
	fatal string
	skip  string
}

func (r *recordingTB) Fatalf(format string, args ...any) { r.fatal = fmt.Sprintf(format, args...) }

func (r *recordingTB) Skipf(format string, args ...any) { r.skip = fmt.Sprintf(format, args...) }

func TestRequireEnvFailsWhenRequired(t *testing.T) {
	const name = "FALCOSIDEKICK_E2E_HARNESS_PROBE"
	for _, tc := range []struct {
		name, value, require string
		want, fatal, skip    string
	}{
		{name: "set", value: "x", require: "1", want: "x"},
		{name: "unset", skip: name + " not set"},
		{name: "unset-required", require: "1", fatal: name + " not set and " + requireSwitch + "=1"},
		{name: "unset-other-switch-value", require: "true", skip: name + " not set"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(name, tc.value)
			t.Setenv(requireSwitch, tc.require)
			tb := &recordingTB{TB: t}
			assert.Equal(t, tc.want, requireEnv(tb, name))
			assert.Equal(t, tc.fatal, tb.fatal)
			assert.Equal(t, tc.skip, tb.skip)
		})
	}
}
