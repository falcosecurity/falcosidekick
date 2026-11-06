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
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

// proxyHost resolves nowhere: only a proxy can deliver to it. Go never proxies localhost.
const proxyHost = "falcosidekick-e2e.invalid"

// forwardProxy answers every absolute-form request as the destination would.
type forwardProxy struct {
	targets []string
	mu      sync.Mutex
}

func (p *forwardProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	p.targets = append(p.targets, r.URL.Host)
	p.mu.Unlock()
	w.WriteHeader(http.StatusOK)
}

func (p *forwardProxy) seen() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.targets...)
}

func TestHTTPOutputsHonorProxyEnvironment(t *testing.T) {
	webhook := outputYAML("webhook", "host: \"http://"+proxyHost+"\"\nruntime:\n  health_check: false")
	for _, tc := range []struct {
		name    string
		noProxy string
		proxied bool
	}{
		{name: "through the proxy", proxied: true},
		{name: "NO_PROXY bypasses it", noProxy: proxyHost},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proxy := &forwardProxy{}
			server := httptest.NewServer(proxy)
			t.Cleanup(server.Close)
			opts := defaultLaunch
			opts.env = []string{"HTTP_PROXY=" + server.URL, "http_proxy=" + server.URL, "NO_PROXY=" + tc.noProxy, "no_proxy=" + tc.noProxy}
			sk := startSidekickWith(t, opts, webhook)
			sk.postEvent(t, newMarker(t))
			st := sk.waitStatus(t, "webhook", func(st outputStatus) bool { return st.SentTotal+st.FailedTotal == 1 })
			if tc.proxied {
				assert.Equal(t, 1, st.SentTotal, st.LastError)
				assert.Equal(t, []string{proxyHost}, proxy.seen())
				return
			}
			assert.Equal(t, 1, st.FailedTotal)
			assert.Empty(t, proxy.seen())
		})
	}
}
