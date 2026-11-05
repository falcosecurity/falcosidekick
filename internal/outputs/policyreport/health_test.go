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

package policyreport

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
)

const (
	testToken      = "kube-secret-token"
	apiPath        = "/apis/openreports.io/v1alpha1"
	clusterGetPath = apiPath + "/clusterreports/" + reportName
)

// apiServer fakes the parts of the Kubernetes API the output uses.
type apiServer struct {
	reports   map[string][]byte
	resources []string
	requests  []string
	discovery int
	cluster   int
	mu        sync.Mutex
}

func newAPIServer() *apiServer {
	return &apiServer{
		resources: []string{"reports", "clusterreports"},
		reports:   map[string][]byte{},
		cluster:   http.StatusNotFound,
	}
}

func writeStatus(w http.ResponseWriter, code int) {
	reason := strings.ReplaceAll(http.StatusText(code), " ", "")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = fmt.Fprintf(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","reason":%q,"message":"user system:anonymous detail","code":%d}`, reason, code)
}

func (s *apiServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = append(s.requests, r.Method+" "+r.URL.Path+" "+r.Header.Get("Authorization"))
	switch {
	case r.URL.Path == apiPath:
		if s.discovery != 0 {
			writeStatus(w, s.discovery)
			return
		}
		list := map[string]any{"kind": "APIResourceList", "groupVersion": "openreports.io/v1alpha1"}
		var resources []map[string]any
		for _, name := range s.resources {
			resources = append(resources, map[string]any{"name": name, "namespaced": name == "reports", "kind": "X", "verbs": []string{"get"}})
		}
		list["resources"] = resources
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(list)
	case r.Method == http.MethodGet && r.URL.Path == clusterGetPath && s.cluster != http.StatusOK:
		writeStatus(w, s.cluster)
	case r.Method == http.MethodGet:
		body, ok := s.reports[r.URL.Path]
		if !ok {
			writeStatus(w, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	case r.Method == http.MethodPost:
		body, _ := io.ReadAll(r.Body)
		var obj map[string]any
		_ = json.Unmarshal(body, &obj)
		meta, _ := obj["metadata"].(map[string]any)
		s.reports[r.URL.Path+"/"+fmt.Sprint(meta["name"])] = body
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(body)
	default:
		writeStatus(w, http.StatusMethodNotAllowed)
	}
}

func (s *apiServer) snapshot() (requests []string, reports map[string][]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	reports = make(map[string][]byte, len(s.reports))
	for k, v := range s.reports {
		reports[k] = v
	}
	return append([]string(nil), s.requests...), reports
}

func driverFor(t *testing.T, url string) *driver {
	t.Helper()
	drv, err := OutputType.New(map[string]any{
		"kubeconfig":      testutil.WriteKubeconfig(t, url, "", testToken),
		"falco_namespace": "falco",
	}, output.Deps{})
	require.NoError(t, err)
	require.NoError(t, drv.Init(context.Background()))
	t.Cleanup(func() { _ = drv.Close() })
	return drv.(*driver)
}

func TestHealthCheck(t *testing.T) {
	tests := []struct {
		setup        func(s *apiServer)
		name         string
		wantErr      string
		misconfigure bool
	}{
		{name: "served, report absent"},
		{name: "served, report present", setup: func(s *apiServer) {
			s.cluster = http.StatusOK
			s.reports[clusterGetPath] = []byte(`{"kind":"ClusterReport","apiVersion":"openreports.io/v1alpha1","metadata":{"name":"x"}}`)
		}},
		{name: "api not served", setup: func(s *apiServer) { s.discovery = http.StatusNotFound }, wantErr: "policyreport discovery: HTTP 404 Not Found", misconfigure: true},
		{name: "rejected credentials", setup: func(s *apiServer) { s.discovery = http.StatusUnauthorized }, wantErr: "HTTP 401 Unauthorized", misconfigure: true},
		{name: "cluster report missing", setup: func(s *apiServer) { s.resources = []string{"reports"} }, wantErr: "openreports.io/v1alpha1 does not serve clusterreports", misconfigure: true},
		{name: "read denied", setup: func(s *apiServer) { s.cluster = http.StatusForbidden }, wantErr: "policyreport read clusterreport: HTTP 403 Forbidden", misconfigure: true},
		{name: "server error", setup: func(s *apiServer) { s.discovery = http.StatusServiceUnavailable }, wantErr: "HTTP 503"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api := newAPIServer()
			if tt.setup != nil {
				tt.setup(api)
			}
			server := httptest.NewServer(api)
			t.Cleanup(server.Close)
			d := driverFor(t, server.URL)

			err := d.HealthCheck(context.Background())
			if tt.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				assert.Equal(t, tt.misconfigure, isMisconfigured(err))
				assert.NotContains(t, err.Error(), "system:anonymous")
				assert.NotContains(t, err.Error(), testToken)
			}
			requests, _ := api.snapshot()
			require.NotEmpty(t, requests)
			assert.True(t, strings.HasPrefix(requests[0], "GET "+apiPath+" "), requests[0])
		})
	}
}

// Over TLS with a trusted CA the kubeconfig token authenticates every request.
func TestHealthCheckTrustedCertificateSendsToken(t *testing.T) {
	api := newAPIServer()
	server := httptest.NewTLSServer(api)
	t.Cleanup(server.Close)
	ca := base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
	drv, err := OutputType.New(map[string]any{"kubeconfig": testutil.WriteKubeconfig(t, server.URL, ca, testToken)}, output.Deps{})
	require.NoError(t, err)
	require.NoError(t, drv.Init(context.Background()))
	require.NoError(t, drv.HealthCheck(context.Background()))
	requests, _ := api.snapshot()
	require.Len(t, requests, 2)
	assert.Equal(t, "GET "+apiPath+" Bearer "+testToken, requests[0])
	assert.Equal(t, "GET "+clusterGetPath+" Bearer "+testToken, requests[1])
}

func isMisconfigured(err error) bool {
	return errors.Is(err, output.ErrMisconfigured)
}

func TestHealthCheckUnreachableIsTransient(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	url := server.URL
	server.Close()
	d := driverFor(t, url)
	err := d.HealthCheck(context.Background())
	require.Error(t, err)
	assert.False(t, isMisconfigured(err))
	assert.Contains(t, err.Error(), "connection refused")
}

func TestHealthCheckUntrustedCertificate(t *testing.T) {
	server := httptest.NewTLSServer(newAPIServer())
	t.Cleanup(server.Close)
	d := driverFor(t, server.URL)
	err := d.HealthCheck(context.Background())
	require.Error(t, err)
	assert.True(t, isMisconfigured(err))
	assert.Contains(t, err.Error(), "TLS certificate verification failed")
}

func TestHealthCheckInvalidDiscoveryBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, "{not json")
	}))
	t.Cleanup(server.Close)
	err := driverFor(t, server.URL).HealthCheck(context.Background())
	require.Error(t, err)
	assert.False(t, isMisconfigured(err))
	assert.Equal(t, "policyreport discovery: invalid JSON", err.Error())
}

// The real client writes to the openreports.io paths with the kubeconfig credentials.
func TestSendThroughAPIServer(t *testing.T) {
	api := newAPIServer()
	server := httptest.NewServer(api)
	t.Cleanup(server.Close)
	d := driverFor(t, server.URL)

	evt := eventIn("prod", "r1", event.PriorityWarning)
	require.NoError(t, d.Send(context.Background(), evt))
	require.NoError(t, d.Send(context.Background(), eventIn("", "r2", event.PriorityError)))

	_, reports := api.snapshot()
	require.Contains(t, reports, apiPath+"/namespaces/prod/reports/"+reportName)
	require.Contains(t, reports, apiPath+"/clusterreports/"+reportName)
	var report map[string]any
	require.NoError(t, json.Unmarshal(reports[apiPath+"/namespaces/prod/reports/"+reportName], &report))
	assert.Equal(t, "openreports.io/v1alpha1", report["apiVersion"])
	assert.Equal(t, "Report", report["kind"])
	results := report["results"].([]any)
	require.Len(t, results, 1)
	assert.Equal(t, "warn", results[0].(map[string]any)["result"])
}

// Send and HealthCheck return once ctx ends on an API server that never answers.
func TestReturnsWhenContextEndsOnSilentServer(t *testing.T) {
	d := driverFor(t, testutil.HangingHTTPServer(t).URL)

	for name, call := range map[string]func(context.Context) error{
		"Send":        func(ctx context.Context) error { return d.Send(ctx, eventIn("", "r", event.PriorityError)) },
		"HealthCheck": d.HealthCheck,
	} {
		t.Run(name, func(t *testing.T) {
			assert.False(t, isMisconfigured(testutil.RequireReturnsOnCancel(t, name, call)))
		})
	}
}
