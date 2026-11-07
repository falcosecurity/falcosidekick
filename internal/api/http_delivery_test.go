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

package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/catalog"
	"github.com/falcosecurity/falcosidekick/internal/database"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/slack"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
	"github.com/falcosecurity/falcosidekick/internal/outputs/webhook"
	"github.com/falcosecurity/falcosidekick/internal/pipeline"
)

func TestHTTPDeliveryStatus_SafeErrorsAndRecovery(t *testing.T) {
	const (
		bearerToken   = "synthetic-delivery-bearer-secret"
		headerToken   = "synthetic-delivery-header-secret"
		locationToken = "synthetic-delivery-location-secret"
		pathToken     = "synthetic-slack-path-secret"
	)
	for _, provider := range []struct {
		outputType output.Type
	}{
		{outputType: webhook.OutputType},
		{outputType: slack.OutputType},
	} {
		t.Run(provider.outputType.Name, func(t *testing.T) {
			type failureCase struct {
				name       string
				wantReason string
				statusCode int
			}
			cases := []failureCase{
				{name: "reflected_non_2xx_body", wantReason: "HTTP 401 Unauthorized", statusCode: http.StatusUnauthorized},
				{name: "cross_origin_redirect", wantReason: "cross-origin redirect denied", statusCode: http.StatusTemporaryRedirect},
			}
			if provider.outputType.Name == slack.OutputType.Name {
				cases = append(cases, failureCase{name: "reflected_protocol_error", wantReason: "unexpected response", statusCode: http.StatusOK})
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					var targetCalls atomic.Int32
					target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						targetCalls.Add(1)
						_, _ = io.WriteString(w, "ok")
					}))
					t.Cleanup(target.Close)

					var recovered atomic.Bool
					var sourceCalls atomic.Int32
					requests := make(chan httpDeliveryRequest, 2)
					source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						sourceCalls.Add(1)
						body, err := io.ReadAll(r.Body)
						select {
						case requests <- httpDeliveryRequest{header: r.Header.Clone(), body: body, method: r.Method, err: err}:
						default:
						}
						if recovered.Load() {
							_, _ = io.WriteString(w, "ok")
							return
						}
						if tc.statusCode == http.StatusTemporaryRedirect {
							w.Header().Set("Location", target.URL+"/"+locationToken+"?token="+headerToken)
						}
						w.WriteHeader(tc.statusCode)
						_, _ = io.WriteString(w, r.Header.Get("Authorization")+" "+r.Header.Get("X-Api-Key")+" "+r.URL.String())
					}))
					t.Cleanup(source.Close)

					cat, err := catalog.New([]output.Type{provider.outputType})
					require.NoError(t, err)
					rig := buildMutationRig(t, database.NewMemory(), cat, true)
					route := map[string]string{"endpoint": "/events"}
					if provider.outputType.Name == slack.OutputType.Name {
						route = map[string]string{"secret_endpoint": "/services/" + pathToken}
					}
					config := map[string]any{
						"host":         source.URL,
						"bearer_token": bearerToken,
						"headers": map[string]any{
							"X-Api-Key": map[string]any{"secrets": []string{headerToken}},
						},
					}
					for key, value := range route {
						config[key] = value
					}
					require.NoError(t, applyErr(rig.Reloader.ApplyOutput(t.Context(), provider.outputType.Name, 0, config)))

					rig.Server.pipeline.ProcessEvent(t.Context(), testutil.CreateValidEvent())
					waitForHTTPDeliveryStatus(t, rig, 0, 1)
					assertHTTPDeliveryProjections(t, rig.Server, provider.outputType.Name, tc.wantReason, 0,
						[]string{bearerToken, headerToken, locationToken, pathToken})
					assert.EqualValues(t, 1, sourceCalls.Load(), "a failed delivery must not be counted as success or retried")
					assert.Zero(t, targetCalls.Load(), "a denied redirect must not contact its destination")
					assertHTTPDeliveryRequest(t, requests, bearerToken, headerToken)

					recovered.Store(true)
					rig.Server.pipeline.ProcessEvent(t.Context(), testutil.CreateValidEvent())
					waitForHTTPDeliveryStatus(t, rig, 1, 1)
					assertHTTPDeliveryProjections(t, rig.Server, provider.outputType.Name, "", 1,
						[]string{bearerToken, headerToken, locationToken, pathToken})
					assert.EqualValues(t, 2, sourceCalls.Load())
					assert.Zero(t, targetCalls.Load())
					assertHTTPDeliveryRequest(t, requests, bearerToken, headerToken)
				})
			}
		})
	}
}

type httpDeliveryRequest struct {
	err    error
	header http.Header
	method string
	body   []byte
}

func assertHTTPDeliveryRequest(t *testing.T, requests <-chan httpDeliveryRequest, bearerToken, headerToken string) {
	t.Helper()
	select {
	case req := <-requests:
		require.NoError(t, req.err)
		assert.Equal(t, http.MethodPost, req.method)
		assert.Equal(t, "Bearer "+bearerToken, req.header.Get("Authorization"))
		assert.Equal(t, headerToken, req.header.Get("X-Api-Key"))
		assert.True(t, json.Valid(req.body), "the actual driver must send a JSON event payload")
		assert.Contains(t, string(req.body), "Write below binary dir")
	default:
		t.Fatal("delivery completed without a captured HTTP request")
	}
}

func waitForHTTPDeliveryStatus(t *testing.T, rig *mutationTestRig, sent, failed int) {
	t.Helper()
	require.Eventually(t, func() bool {
		statuses := rig.Dispatcher.CollectStatus()
		if len(statuses) != 1 {
			return false
		}
		st := statuses[0]
		if st.SentTotal != sent || st.FailedTotal != failed || st.QueueDepth != 0 {
			return false
		}
		if sent == 0 {
			return st.LastError != "" && st.Status == pipeline.HealthError
		}
		return st.LastError == "" && st.Status == pipeline.HealthOK && !st.LastSuccess.IsZero()
	}, 5*time.Second, time.Millisecond, "queued HTTP delivery did not reach its expected terminal state")
}

func assertHTTPDeliveryProjections(t *testing.T, srv *Server, name, wantReason string, sent int, secrets []string) {
	t.Helper()
	const (
		statusPath    = "/api/v1/pipeline/status"
		compositePath = "/api/v1/pipeline"
	)
	for _, path := range []string{statusPath, statusPath + "/" + name, compositePath} {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, http.NoBody)
		resp, err := srv.app.Test(req)
		require.NoError(t, err)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, resp.Body.Close())
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode, "%s", path)
		for _, secret := range secrets {
			assert.NotContains(t, string(body), secret, "%s must not expose credentials", path)
		}

		var st pipeline.OutputStatus
		switch path {
		case statusPath:
			var got struct {
				Outputs []pipeline.OutputStatus `json:"outputs"`
			}
			require.NoError(t, json.Unmarshal(body, &got))
			require.Len(t, got.Outputs, 1)
			st = got.Outputs[0]
		case compositePath:
			var got struct {
				Outputs map[string]outputConfigResponse `json:"outputs"`
				Status  []pipeline.OutputStatus         `json:"status"`
			}
			require.NoError(t, json.Unmarshal(body, &got))
			require.Contains(t, got.Outputs, name)
			assert.True(t, got.Outputs[name].SecretFields["/bearer_token"])
			assert.True(t, got.Outputs[name].SecretFields["/headers/X-Api-Key/secrets"])
			require.Len(t, got.Status, 1)
			st = got.Status[0]
		default:
			require.NoError(t, json.Unmarshal(body, &st))
		}

		assert.Equal(t, name, st.Name, "%s", path)
		assert.Equal(t, sent, st.SentTotal, "%s", path)
		assert.Equal(t, 1, st.FailedTotal, "%s", path)
		assert.Zero(t, st.DroppedTotal, "%s", path)
		assert.Zero(t, st.QueueDepth, "%s", path)
		if wantReason != "" {
			assert.Equal(t, pipeline.HealthError, st.Status, "%s", path)
			assert.Contains(t, st.LastError, name, "%s", path)
			assert.Contains(t, st.LastError, wantReason, "%s", path)
			assert.True(t, st.LastSuccess.IsZero(), "%s", path)
		} else {
			assert.Equal(t, pipeline.HealthOK, st.Status, "%s", path)
			assert.Empty(t, st.LastError, "%s", path)
			assert.False(t, st.LastSuccess.IsZero(), "%s", path)
		}
	}
}
