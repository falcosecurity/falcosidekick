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

package testutil

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain/output"
)

// OutputTestCase defines a test scenario for an output.
type OutputTestCase struct {
	ValidateReq  func(t *testing.T, req *http.Request, body []byte)
	Config       map[string]any
	Name         string
	AddressField string
	MockStatus   int
	AddressSlice bool
	ExpectError  bool
}

// RunOutputTests executes test cases against an output type using a mock HTTP server.
func RunOutputTests(t *testing.T, outputType output.Type, cases []OutputTestCase) {
	t.Helper()

	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			var capturedReq *http.Request
			var capturedBody []byte

			status := tc.MockStatus
			if status == 0 {
				status = http.StatusOK
			}

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				capturedReq = r.Clone(r.Context())
				capturedBody, _ = io.ReadAll(r.Body)
				w.WriteHeader(status)
			}))
			defer server.Close()

			cfg := make(map[string]any)
			for k, v := range tc.Config {
				cfg[k] = v
			}

			if tc.AddressField != "" {
				if tc.AddressSlice {
					cfg[tc.AddressField] = []string{server.URL}
				} else {
					cfg[tc.AddressField] = server.URL
				}
			}

			driver, err := outputType.New(cfg, output.Deps{})
			require.NoError(t, err)

			require.NoError(t, driver.Init(context.Background()))

			err = driver.Send(context.Background(), CreateValidEvent())

			if tc.ExpectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			if tc.ValidateReq != nil {
				tc.ValidateReq(t, capturedReq, capturedBody)
			}
		})
	}
}
