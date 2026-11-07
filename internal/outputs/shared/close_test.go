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

package shared_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
)

// closeBound is how long Close may take on a destination that never answers.
const closeBound = 5 * time.Second

// A replaced or removed output is closed while its last delivery may still be waiting, after a
// failed Init, and again by later cleanup: every output must survive all three without hanging.
func TestEveryOutputClosesAfterReplacementAndTwice(t *testing.T) {
	cases := silentCases(t)
	cases = append(cases, silentCase{name: "inmemory", config: func(string) map[string]any { return map[string]any{} }})
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			requireClosesWithin(t, tt.build(t), "before Init")

			driver := tt.newDriver(t)
			if tt.name == "inmemory" {
				require.NoError(t, driver.Send(context.Background(), testutil.CreateValidEvent()))
			} else {
				_ = testutil.RequireReturnsOnCancel(t, "Send", func(ctx context.Context) error {
					return driver.Send(ctx, testutil.CreateValidEvent())
				})
			}
			requireClosesWithin(t, driver, "after a canceled delivery")
			requireClosesWithin(t, driver, "a second time")
			assert.NotPanics(t, func() {
				ctx, cancel := context.WithTimeout(context.Background(), testutil.CancelAfter)
				defer cancel()
				_ = driver.Send(ctx, testutil.CreateValidEvent())
			}, "a delivery after Close fails, it does not panic")
		})
	}
}

func requireClosesWithin(t *testing.T, driver output.Driver, when string) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- assert.AnError
			}
		}()
		done <- driver.Close()
	}()
	select {
	case err := <-done:
		require.NotErrorIs(t, err, assert.AnError, "Close %s panicked", when)
	case <-time.After(closeBound):
		t.Fatalf("Close %s did not return within %s", when, closeBound)
	}
}
