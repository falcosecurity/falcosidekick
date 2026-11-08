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

package elasticsearch

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
)

type failingJSONValue struct {
	err error
}

func (v failingJSONValue) MarshalJSON() ([]byte, error) { return nil, v.err }

func TestElasticsearchMarshalSafeDiagnostics(t *testing.T) {
	for _, batch := range []bool{false, true} {
		name := "single"
		if batch {
			name = "batch"
		}
		t.Run(name, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				w.WriteHeader(http.StatusOK)
			}))
			t.Cleanup(server.Close)
			d, err := createOutput(map[string]any{"host": server.URL}, output.Deps{})
			require.NoError(t, err)
			cause := errors.New("MARSHAL_SECRET")
			evt := testutil.CreateValidEvent()
			evt.OutputFields["private"] = failingJSONValue{err: cause}

			if batch {
				err = d.(output.BatchSender).SendBatch(context.Background(), []*event.Event{evt})
			} else {
				err = d.Send(context.Background(), evt)
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), "marshal")
			assert.Contains(t, err.Error(), "cannot encode payload")
			assert.NotContains(t, err.Error(), cause.Error())
			assert.ErrorIs(t, err, cause)
			var marshalErr *json.MarshalerError
			assert.ErrorAs(t, err, &marshalErr)
			var diagnostic *shared.DeliveryError
			assert.ErrorAs(t, err, &diagnostic)
			assert.Zero(t, requests.Load(), "encoding failure must precede network delivery")
		})
	}
}

func TestElasticsearchCommonCases(t *testing.T) {
	testutil.RunOutputTests(t, &OutputType, []testutil.OutputTestCase{
		{Name: "sends valid event", AddressField: "host"},
		{Name: "returns error on server 500", AddressField: "host", MockStatus: http.StatusInternalServerError, ExpectError: true},
	})
}

func TestElasticsearchPayloadFormat(t *testing.T) {
	testutil.RunOutputTests(t, &OutputType, []testutil.OutputTestCase{
		{
			Name:         "includes @timestamp in body",
			AddressField: "host",
			ValidateReq: func(t *testing.T, _ *http.Request, body []byte) {
				assert.Contains(t, string(body), "@timestamp")
			},
		},
		{
			Name:         "creates the document with the event UUID as id",
			AddressField: "host",
			Config:       map[string]any{"index": "security", "index_suffix": "none"},
			ValidateReq: func(t *testing.T, req *http.Request, _ []byte) {
				assert.Equal(t, http.MethodPut, req.Method)
				assert.Equal(t, "/security/_create/test-uuid-001", req.URL.Path)
			},
		},
		{
			Name:         "applies basic auth",
			AddressField: "host",
			Config:       map[string]any{"username": "elastic", "password": "secret"},
			ValidateReq: func(t *testing.T, req *http.Request, _ []byte) {
				user, pass, ok := req.BasicAuth()
				require.True(t, ok)
				assert.Equal(t, "elastic", user)
				assert.Equal(t, "secret", pass)
			},
		},
		{
			Name:         "applies api key auth",
			AddressField: "host",
			Config:       map[string]any{"api_key": "mykey123"},
			ValidateReq: func(t *testing.T, req *http.Request, _ []byte) {
				assert.Equal(t, "ApiKey mykey123", req.Header.Get("Authorization"))
			},
		},
		{
			Name:         "flattens field names when configured",
			AddressField: "host",
			Config:       map[string]any{"flatten_fields": true},
			ValidateReq: func(t *testing.T, _ *http.Request, body []byte) {
				assert.NotContains(t, string(body), `"fd.name"`)
			},
		},
		{
			Name:         "includes pipeline query parameter",
			AddressField: "host",
			Config:       map[string]any{"pipeline": "my-ingest"},
			ValidateReq: func(t *testing.T, req *http.Request, _ []byte) {
				assert.Equal(t, "my-ingest", req.URL.Query().Get("pipeline"))
			},
		},
	})
}

func TestElasticsearchCreateValidation(t *testing.T) {
	_, err := createOutput(map[string]any{}, output.Deps{})
	assert.Error(t, err, "missing url must fail")
}

func TestElasticsearchHealthCheck(t *testing.T) {
	for _, tc := range []struct {
		name          string
		status        int
		misconfigured bool
	}{
		{name: "ok", status: http.StatusOK},
		{name: "rejected credentials", status: http.StatusUnauthorized, misconfigured: true},
		{name: "wrong base path", status: http.StatusNotFound, misconfigured: true},
		{name: "no monitor privilege", status: http.StatusForbidden},
		{name: "unavailable", status: http.StatusServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var path, method string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				path, method = r.URL.Path, r.Method
				w.WriteHeader(tc.status)
			}))
			t.Cleanup(server.Close)
			d, err := OutputType.New(map[string]any{"host": server.URL, "base_path": "/es"}, output.Deps{})
			require.NoError(t, err)

			err = d.HealthCheck(context.Background())
			assert.Equal(t, http.MethodGet, method)
			assert.Equal(t, "/es", path)
			if tc.status == http.StatusOK {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Equal(t, tc.misconfigured, errors.Is(err, output.ErrMisconfigured))
		})
	}
}

func TestElasticsearchClose(t *testing.T) {
	d, err := OutputType.New(map[string]any{"host": "http://127.0.0.1:1"}, output.Deps{})
	require.NoError(t, err)
	assert.NoError(t, d.Close())
	assert.NoError(t, d.Close(), "Close is idempotent")
}

// The index follows the event time in UTC, not the delivery clock: the last second of a year,
// delivered later, stays in that day, month and year.
func TestResolveIndexFollowsTheEventTime(t *testing.T) {
	lastSecond := time.Date(2026, 1, 1, 0, 59, 59, 0, time.FixedZone("CET", 3600))
	tests := []struct {
		suffix, want string
	}{
		{"daily", "falco-2025.12.31"},
		{"monthly", "falco-2025.12"},
		{"annually", "falco-2025"},
		{"none", "falco"},
	}
	for _, tt := range tests {
		t.Run(tt.suffix, func(t *testing.T) {
			o := &driver{cfg: config{Index: "falco", Suffix: tt.suffix}}
			assert.Equal(t, tt.want, o.resolveIndex(&event.Event{Time: lastSecond}))
		})
	}

	o := &driver{cfg: config{Index: "falco", Suffix: "daily"}}
	assert.Equal(t, "falco-"+time.Now().UTC().Format("2006.01.02"), o.resolveIndex(&event.Event{}), "no event time: the delivery day")
}

func TestFlattenFieldsReplacesDotsAndPreservesValues(t *testing.T) {
	testutil.RunOutputTests(t, &OutputType, []testutil.OutputTestCase{
		{
			Name:         "flattened field names use underscores",
			AddressField: "host",
			Config:       map[string]any{"flatten_fields": true},
			ValidateReq: func(t *testing.T, _ *http.Request, body []byte) {
				bodyStr := string(body)
				assert.NotContains(t, bodyStr, `"fd.name"`, "dotted field name must be gone")
				assert.Contains(t, bodyStr, `"fd_name"`, "flattened field name must be present")
				assert.Contains(t, bodyStr, "/bin/hack", "field value must survive flattening")
			},
		},
	})
}

func TestElasticsearchSendStatus(t *testing.T) {
	for _, tc := range []struct {
		name, uuid, wantRequest string
		status                  int
		wantErr                 bool
	}{
		{name: "created", uuid: "id-1", status: http.StatusCreated, wantRequest: "PUT /falco/_create/id-1"},
		{name: "already indexed", uuid: "id-1", status: http.StatusConflict, wantRequest: "PUT /falco/_create/id-1"},
		{name: "rejected", uuid: "id-1", status: http.StatusBadRequest, wantRequest: "PUT /falco/_create/id-1", wantErr: true},
		{name: "escaped id", uuid: "a/b", status: http.StatusCreated, wantRequest: "PUT /falco/_create/a%2Fb"},
		{name: "without uuid", status: http.StatusCreated, wantRequest: "POST /falco/_doc"},
		{name: "conflict without uuid", status: http.StatusConflict, wantRequest: "POST /falco/_doc", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var request string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				request = r.Method + " " + r.URL.EscapedPath()
				w.WriteHeader(tc.status)
			}))
			t.Cleanup(server.Close)
			d, err := createOutput(map[string]any{"host": server.URL, "index_suffix": "none"}, output.Deps{})
			require.NoError(t, err)
			evt := testutil.CreateValidEvent()
			evt.UUID = tc.uuid

			err = d.Send(context.Background(), evt)
			assert.Equal(t, tc.wantRequest, request)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestElasticsearchAPIKeyValidation(t *testing.T) {
	for _, tc := range []struct {
		config map[string]any
		name   string
		want   string
	}{
		{name: "with username", config: map[string]any{"api_key": "k", "username": "u"}, want: "cannot combine api_key with basic auth or bearer_token"},
		{name: "with password", config: map[string]any{"api_key": "k", "password": "p"}, want: "cannot combine api_key with basic auth or bearer_token"},
		{name: "with bearer token", config: map[string]any{"api_key": "k", "bearer_token": "t"}, want: "cannot combine api_key with basic auth or bearer_token"},
		{name: "with authorization header", config: map[string]any{"api_key": "k", "headers": map[string]any{"authorization": map[string]any{"secrets": []any{"x"}}}}, want: "cannot combine api_key with an authorization header"},
		{name: "invalid header value", config: map[string]any{"api_key": "k\nX-Injected: 1"}, want: "invalid header value"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.config["host"] = "https://es.example"
			_, err := createOutput(tc.config, output.Deps{})
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
			assert.NotContains(t, err.Error(), "X-Injected")
		})
	}
}
