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
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"

	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/pipeline"
)

const (
	uiTestIndexBody = "<!doctype html><html><body>ui-test-index</body></html>"
	uiTestAssetBody = "console.log('ui-test-asset');\n"
)

func newUITestFS() fstest.MapFS {
	return fstest.MapFS{
		"index.html":    {Data: []byte(uiTestIndexBody)},
		"assets/app.js": {Data: []byte(uiTestAssetBody)},
	}
}

func TestRegisterStaticUI_NoAssets_NoInterception(t *testing.T) {
	srv := buildUITestServer(t, nil, nil)

	root, err := srv.app.Test(httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody))
	require.NoError(t, err)
	defer root.Body.Close()
	assert.Equal(t, http.StatusNotFound, root.StatusCode, "without UI assets the management listener serves only the API")

	ver, err := srv.app.Test(httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/version", http.NoBody))
	require.NoError(t, err)
	defer ver.Body.Close()
	assert.Equal(t, http.StatusOK, ver.StatusCode)
}

// D2: ingestion serves Falco, probes and Prometheus; management serves the API and the UI; neither serves the other.
// Without read and idle deadlines a client that never finishes its request holds a connection
// forever, and Shutdown does not close idle keep-alive connections.
func TestListenersBoundSlowClients(t *testing.T) {
	srv := buildTestServer(t, nil)
	for name, app := range map[string]*fiber.App{"ingestion": srv.ingestion, "management": srv.app} {
		cfg := app.Config()
		assert.Equal(t, 30*time.Second, cfg.ReadTimeout, name)
		assert.Equal(t, 30*time.Second, cfg.WriteTimeout, name)
		assert.Equal(t, 2*time.Minute, cfg.IdleTimeout, name)
		assert.True(t, cfg.Immutable, name)
	}
}

func TestListenersAreSeparate(t *testing.T) {
	srv := buildUITestServer(t, newUITestFS(), prometheus.NewRegistry())
	status := func(app *fiber.App, method, path string) int {
		var body io.Reader = http.NoBody
		if method == http.MethodPost {
			body = bytes.NewReader(createValidEventJSON())
		}
		resp, err := app.Test(httptest.NewRequestWithContext(t.Context(), method, path, body))
		require.NoError(t, err)
		defer resp.Body.Close()
		return resp.StatusCode
	}
	for _, tc := range []struct {
		method, path string
		ingestion    int
		management   int
	}{
		{method: http.MethodPost, path: "/", ingestion: http.StatusOK, management: http.StatusMethodNotAllowed},
		{method: http.MethodGet, path: "/healthz", ingestion: http.StatusOK, management: http.StatusOK},
		{method: http.MethodGet, path: "/metrics", ingestion: http.StatusOK},
		{method: http.MethodGet, path: "/api/v1/pipeline/status", ingestion: http.StatusNotFound, management: http.StatusOK},
		{method: http.MethodGet, path: "/api/v1/events/search", ingestion: http.StatusNotFound},
		{method: http.MethodGet, path: "/", ingestion: http.StatusMethodNotAllowed, management: http.StatusOK},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			assert.Equal(t, tc.ingestion, status(srv.ingestion, tc.method, tc.path), "ingestion")
			if tc.management != 0 {
				assert.Equal(t, tc.management, status(srv.app, tc.method, tc.path), "management")
			}
		})
	}
	resp, err := srv.app.Test(httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", http.NoBody))
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.NotContains(t, string(body), "# HELP", "metrics are served on ingestion only")
}

func TestRegisterStaticUI_AssetsPresent_ServesIndex(t *testing.T) {
	srv := buildUITestServer(t, newUITestFS(), nil)

	resp, err := srv.app.Test(httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, readErr := io.ReadAll(resp.Body)
	require.NoError(t, readErr)
	assert.Equal(t, uiTestIndexBody, string(body))
	assert.Contains(t, resp.Header.Get("Content-Type"), "text/html")
}

func TestRegisterStaticUI_AssetsPresent_ServesAsset(t *testing.T) {
	srv := buildUITestServer(t, newUITestFS(), nil)

	resp, err := srv.app.Test(httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/assets/app.js", http.NoBody))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, readErr := io.ReadAll(resp.Body)
	require.NoError(t, readErr)
	assert.Equal(t, uiTestAssetBody, string(body))
}

func TestRegisterStaticUI_AssetsPresent_SkipsAPIPaths(t *testing.T) {
	srv := buildUITestServer(t, newUITestFS(), nil)

	resp, err := srv.app.Test(httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/version", http.NoBody))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, readErr := io.ReadAll(resp.Body)
	require.NoError(t, readErr)
	assert.Contains(t, string(body), "version", "API path must return JSON, not index.html")
	assert.NotEqual(t, uiTestIndexBody, string(body))
}

func TestRegisterStaticUI_AssetsPresent_UnregisteredAPIPathReturns404(t *testing.T) {
	srv := buildUITestServer(t, newUITestFS(), nil)

	resp, err := srv.app.Test(httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/this-does-not-exist", http.NoBody))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)

	body, readErr := io.ReadAll(resp.Body)
	require.NoError(t, readErr)
	assert.NotContains(t, string(body), uiTestIndexBody,
		"unregistered /api/ paths must not fall through to index.html; skipAPIPaths must skip the static middleware")
}

func TestRegisterStaticUI_AssetsPresent_UnknownRouteServesSPA(t *testing.T) {
	srv := buildUITestServer(t, newUITestFS(), nil)

	resp, err := srv.app.Test(httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/does-not-exist", http.NoBody))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"extensionless unknown routes must fall back to index.html so React Router can resolve them client-side")
	body, readErr := io.ReadAll(resp.Body)
	require.NoError(t, readErr)
	assert.Contains(t, string(body), uiTestIndexBody)
}

func TestRegisterStaticUI_AssetsPresent_MissingStaticFileReturns404(t *testing.T) {
	srv := buildUITestServer(t, newUITestFS(), nil)

	resp, err := srv.app.Test(httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/missing-asset.png", http.NoBody))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode,
		"requests with an extension must never fall through to index.html")
}

func TestRegisterStaticUI_AssetsPresent_HeadMirrorsGet(t *testing.T) {
	srv := buildUITestServer(t, newUITestFS(), nil)

	resp, err := srv.app.Test(httptest.NewRequestWithContext(t.Context(), http.MethodHead, "/", http.NoBody))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Content-Type"), "text/html")
}

func TestRegisterStaticUI_NegotiatesContentEncoding(t *testing.T) {
	decoders := map[string]func(dst, src []byte) ([]byte, error){
		"br":   fasthttp.AppendUnbrotliBytes,
		"zstd": fasthttp.AppendUnzstdBytes,
		"gzip": fasthttp.AppendGunzipBytes,
	}
	tests := []struct {
		accept string
		want   string
	}{
		{accept: "gzip, deflate, br", want: "br"},
		{accept: "gzip", want: "gzip"},
		{accept: "zstd;q=1, br;q=0.5", want: "zstd"},
		{accept: "", want: ""},
	}
	srv := buildUITestServer(t, newUITestFS(), nil)
	for _, tt := range tests {
		t.Run(tt.accept, func(t *testing.T) {
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
			req.Header.Set("Accept-Encoding", tt.accept)
			resp, err := srv.app.Test(req)
			require.NoError(t, err)
			defer resp.Body.Close()

			require.Equal(t, http.StatusOK, resp.StatusCode, "browsers always send Accept-Encoding; GET / must not fail on it")
			require.Equal(t, tt.want, resp.Header.Get("Content-Encoding"))
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			if decode, compressed := decoders[tt.want]; compressed {
				body, err = decode(nil, body)
				require.NoError(t, err)
			}
			assert.Equal(t, uiTestIndexBody, string(body))
		})
	}
}

func TestServerConfigUIAssetsOptional(t *testing.T) {
	enricher, err := pipeline.NewEnricher(output.EnricherConfig{
		TruncateEventThreshold: 4096,
		TruncateFieldThreshold: 512,
	})
	require.NoError(t, err)
	p, err := pipeline.NewPipeline(enricher, pipeline.NewDispatcher(nil), nil)
	require.NoError(t, err)

	srv, err := NewServer(&ServerConfig{Pipeline: p, Catalog: newTestCatalog(t), UIAssets: nil, Config: testConfig(t)})
	require.NoError(t, err, "NewServer must accept UIAssets: nil")
	assert.NotNil(t, srv)
}
